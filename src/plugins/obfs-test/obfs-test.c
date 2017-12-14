#include <stdlib.h>
#include <err.h>
#include "openvpn-plugin.h"

/* 
 */

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

    out->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_SOCKET_INTERCEPT);
    out->handle = (openvpn_plugin_handle_t *) context;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

err:
    free_context(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}
