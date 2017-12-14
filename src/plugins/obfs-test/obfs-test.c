#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "openvpn-plugin.h"
#include "openvpn-vsocket.h"

static void initialize_socket_vtab(void);

struct obfs_test_context
{
    struct openvpn_plugin_callbacks *global_vtab;
};

static void
free_context(struct obfs_test_context *context)
{
    if (!context)
        return;
    free(context);
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(int version, struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *out)
{
    struct obfs_test_context *context;

    context = (struct obfs_test_context *) calloc(1, sizeof(struct obfs_test_context));
    if (!context)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    context->global_vtab = args->callbacks;
    initialize_socket_vtab();

    out->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_SOCKET_INTERCEPT);
    out->handle = (openvpn_plugin_handle_t *) context;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

err:
    free_context(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    free_context((struct obfs_test_context *) handle);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(int version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr)
{
    /* We don't ask for any bits that use this interface. */
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

struct obfs_test_socket
{
    struct openvpn_vsocket_handle handle;
    int fd;
    unsigned last_rwflags;
};

static struct openvpn_vsocket_vtab obfs_test_socket_vtab;

static void
free_socket(struct obfs_test_socket *sock)
{
    if (!sock)
        return;
    if (sock->fd != -1)
        close(sock->fd);
    free(sock);
}

static in_port_t
munge_port(in_port_t port)
{
    return port ^ 15;
}

/* Reversible. */
static void
munge_addr(struct sockaddr *addr, socklen_t len)
{
    struct sockaddr_in *inet;
    struct sockaddr_in6 *inet6;

    switch (addr->sa_family)
    {
        case AF_INET:
            inet = (struct sockaddr_in *) addr;
            inet->sin_port = munge_port(inet->sin_port);
            break;

        case AF_INET6:
            inet6 = (struct sockaddr_in6 *) addr;
            inet6->sin6_port = munge_port(inet6->sin6_port);
            break;

        default:
            break;
    }
}

/* TODO: need to provide plugin handle here */
static openvpn_vsocket_handle_t
obfs_test_bind(const struct sockaddr *addr, socklen_t len)
{
    struct obfs_test_socket *sock = NULL;
    struct sockaddr *addr_rev = NULL;

    addr_rev = calloc(1, len);
    if (!addr_rev)
        goto error;
    memcpy(addr_rev, addr, len);
    munge_addr(addr_rev, len);

    sock = calloc(1, sizeof(struct obfs_test_socket));
    if (!sock)
        goto error;
    sock->handle.vtab = &obfs_test_socket_vtab;

    sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd == -1)
        goto error;
    if (fcntl(sock->fd, F_SETFL, fcntl(sock->fd, F_GETFL) | O_NONBLOCK))
        goto error;
    
    if (bind(sock->fd, addr_rev, len))
        goto error;
    free(addr_rev);
    return &sock->handle;

error:
    free_socket(sock);
    free(addr_rev);
    return NULL;
}

static void
obfs_test_request_event(openvpn_vsocket_handle_t handle,
                        openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    /* FIXME: this assumes one-shot events. The fast-mode/non-fast-mode distinction in
       the core event loop is awkward here. */
    warnx("obfs-test: request-event: %d", rwflags);
    if (rwflags)
        event_set->vtab->set_event(event_set, ((struct obfs_test_socket *) handle)->fd,
                                   rwflags, handle);
}

static bool
obfs_test_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    warnx("obfs-test: update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle)
        return false;
    ((struct obfs_test_socket *) handle)->last_rwflags = rwflags;
    return true;
}

static unsigned
obfs_test_pump(openvpn_vsocket_handle_t handle)
{
    return ((struct obfs_test_socket *) handle)->last_rwflags;
}

/* Six fixed bytes, six repeated bytes. It's only a silly transformation. */
#define MUNGE_OVERHEAD 12

static ssize_t
unmunge_buf(char *buf, size_t len)
{
    int i;

    if (len < 6)
        goto bad;
    for (i = 0; i < 6; i++)
    {
        if (buf[i] != i)
            goto bad;
    }

    for (i = 0; i < 6 && (6 + 2*i) < len; i++)
    {
        if (len < (6 + 2*i + 1) || buf[6 + 2*i] != buf[6 + 2*i + 1])
            goto bad;
        buf[i] = buf[6 + 2*i];
    }

    if (len > 18)
    {
        memmove(buf + 6, buf + 18, len - 18);
        len -= 12;
    }
    else
    {
        len -= 6;
        len /= 2;
    }

    return len;

bad:
    /* TODO: this really isn't the best way to report this error */
    errno = EIO;
    return -1;
}

/* out must have space for len+MUNGE_OVERHEAD bytes. out and in must
   not overlap. */
static size_t
munge_buf(char *out, const char *in, size_t len)
{
    int i, n;
    size_t out_len = 6;

    for (i = 0; i < 6; i++)
        out[i] = i;
    n = len < 6 ? len : 6;
    for (i = 0; i < n; i++)
        out[6 + 2*i] = out[6 + 2*i + 1] = in[i];
    if (len > 6)
    {
        memmove(out + 18, in + 6, len - 6);
        out_len = len + 12;
    }
    else
    {
        out_len = 6 + 2*len;
    }

    return out_len;
}

static ssize_t
obfs_test_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                   struct sockaddr *addr, socklen_t *addrlen)
{
    int fd = ((struct obfs_test_socket *) handle)->fd;
    ssize_t result = recvfrom(fd, buf, len, 0, addr, addrlen);
    if (*addrlen > 0)
        munge_addr(addr, *addrlen);
    if (result > 0)
        result = unmunge_buf(buf, result);
    return result;
}

static ssize_t
obfs_test_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                 const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = ((struct obfs_test_socket *) handle)->fd;
    struct sockaddr *addr_rev = calloc(1, addrlen);
    void *buf_munged = malloc(len + MUNGE_OVERHEAD);
    size_t len_munged;
    ssize_t result;
    if (!addr_rev || !buf_munged)
        goto error;

    memcpy(addr_rev, addr, addrlen);
    munge_addr(addr_rev, addrlen);
    len_munged = munge_buf(buf_munged, buf, len);
    result = sendto(fd, buf_munged, len_munged, 0, addr_rev, addrlen);
    /* FIXME: Doesn't handle partial transfers. (That might not be an
       issue here anyway?) This is just here to preserve the expected
       invariant of return value <= len. */
    if (result > len)
        result = len;
    free(addr_rev);
    free(buf_munged);
    return result;

error:
    free(addr_rev);
    free(buf_munged);
    return -1;
}

static void
obfs_test_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct obfs_test_socket *) handle);
}

static void
initialize_socket_vtab(void)
{
    obfs_test_socket_vtab.bind = obfs_test_bind;
    obfs_test_socket_vtab.request_event = obfs_test_request_event;
    obfs_test_socket_vtab.update_event = obfs_test_update_event;
    obfs_test_socket_vtab.pump = obfs_test_pump;
    obfs_test_socket_vtab.recvfrom = obfs_test_recvfrom;
    obfs_test_socket_vtab.sendto = obfs_test_sendto;
    obfs_test_socket_vtab.close = obfs_test_close;
}

OPENVPN_EXPORT void *
openvpn_plugin_get_vtab_v1(int selector, size_t *size_out)
{
    switch (selector)
    {
        case OPENVPN_VTAB_SOCKET_INTERCEPT_SOCKET_V1:
            *size_out = sizeof(struct openvpn_vsocket_vtab);
            return &obfs_test_socket_vtab;

        default:
            return NULL;
    }
}
