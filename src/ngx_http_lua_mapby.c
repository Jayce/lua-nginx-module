
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_cache.h"
#include "ngx_http_lua_mapby.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_directive.h"
#include "ngx_http_lua_exception.h"


typedef struct {
    ngx_http_variable_t        *var;
    u_char                     *script_key;
    ngx_str_t                   script;
    int                         ref;

    unsigned                    evaluating:1;
} ngx_http_lua_map_ctx_t;


static ngx_int_t ngx_http_lua_map_by_lua_chunk(lua_State *L, ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_lua_map_by_lua_init(ngx_http_request_t *r);


static ngx_int_t ngx_http_lua_map_evaluating = 0;


static ngx_int_t
ngx_http_lua_map_by_lua_chunk(lua_State *L, ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                  *err_msg, *value;
    size_t                   len;
    ngx_int_t                rc;

    lua_atpanic(L, ngx_http_lua_atpanic);

    /* init nginx context in Lua VM */
    ngx_http_lua_set_req(L, r);

#ifndef OPENRESTY_LUAJIT
    ngx_http_lua_create_new_globals_table(L, 0 /* narr */, 1 /* nrec */);

    /* {{{ make new env inheriting main thread's globals table */
    lua_createtable(L, 0, 1 /* nrec */);   /* the metatable for the new env */
    ngx_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /* setmetatable({}, {__index = _G}) */
    /* }}} */

    lua_setfenv(L, -2);    /* set new running env for the code closure */
#endif /* OPENRESTY_LUAJIT */

    NGX_LUA_EXCEPTION_TRY {
        lua_pushcfunction(L, ngx_http_lua_traceback);
        lua_insert(L, 1);  /* put it under chunk and args */

        /* protected call user code */
        rc = lua_pcall(L, 0, 1, 1);

        lua_remove(L, 1);  /* remove traceback function */

        dd("rc == %d", (int) rc);

        if (rc != 0) {
            /* error occurred when running loaded code */
            err_msg = (u_char *) lua_tolstring(L, -1, &len);

            if (err_msg == NULL) {
                err_msg = (u_char *) "unknown reason";
                len = sizeof("unknown reason") - 1;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "failed to run map_by_lua*: %*s", len, err_msg);

            lua_settop(L, 0); /* clear remaining elems on stack */

            return NGX_ERROR;
        }

        value = (u_char *) lua_tolstring(L, -1, &len);

        if (value) {
            v->data = ngx_palloc(r->pool, len);
            if (v->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(v->data, value, len);
            v->len = len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

        } else {
            v->data = NULL;
            v->len = 0;
        }

    } NGX_LUA_EXCEPTION_CATCH {

        dd("nginx execution restored");
        return NGX_ERROR;
    }

    lua_settop(L, 0); /*  clear remaining elems on stack */
    return rc;
}


static ngx_int_t
ngx_http_lua_map_by_lua_init(ngx_http_request_t *r)
{
    lua_State                   *L;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_cleanup_t          *cln;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        ctx = ngx_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

    } else {
        L = ngx_http_lua_get_lua_vm(r, ctx);
        ngx_http_lua_reset_ctx(r, L, ctx);
    }

    if (ctx->cleanup == NULL) {
        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    ctx->context = NGX_HTTP_LUA_CONTEXT_MAP;
    return NGX_OK;
}


ngx_int_t
ngx_http_lua_map_handler_inline(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    lua_State          *L;
    ngx_int_t           rc;

    ngx_http_lua_map_ctx_t  *ctx = (ngx_http_lua_map_ctx_t *) data;

    if (ctx->evaluating || ngx_http_lua_map_evaluating) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "map_by_lua*: recursion while evaluating variable \"%V\"",
                            &ctx->var->name);
        return NGX_ERROR;
    }

    ngx_http_lua_map_evaluating++;
    ctx->evaluating = 1;

    if (ngx_http_lua_map_by_lua_init(r) != NGX_OK) {
        return NGX_ERROR;
    }

    L = ngx_http_lua_get_lua_vm(r, NULL);

    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       ctx->script.data,
                                       ctx->script.len,
                                       &ctx->ref,
                                       ctx->script_key,
                                       "=map_by_lua");
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_http_lua_assert(lua_isfunction(L, -1));

    rc = ngx_http_lua_map_by_lua_chunk(L, r, v, data);
    ngx_http_lua_map_evaluating--;
    ctx->evaluating = 0;
    return rc;
}


ngx_int_t
ngx_http_lua_map_handler_file(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    lua_State          *L;
    ngx_int_t           rc;

    ngx_http_lua_map_ctx_t  *ctx = (ngx_http_lua_map_ctx_t *) data;

    if (ctx->evaluating || ngx_http_lua_map_evaluating) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "map_by_lua*: cycle while evaluating variable \"%V\"",
                            &ctx->var->name);
        return NGX_ERROR;
    }

    ngx_http_lua_map_evaluating++;
    ctx->evaluating = 1;

    if (ngx_http_lua_map_by_lua_init(r) != NGX_OK) {
        return NGX_ERROR;
    }

    L = ngx_http_lua_get_lua_vm(r, NULL);

    rc = ngx_http_lua_cache_loadfile(r->connection->log, L,
                                       ctx->script.data,
                                       &ctx->ref,
                                       ctx->script_key);
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_http_lua_assert(lua_isfunction(L, -1));

    rc = ngx_http_lua_map_by_lua_chunk(L, r, v, data);
    ngx_http_lua_map_evaluating--;
    ctx->evaluating = 0;
    return rc;
}


char *
ngx_http_lua_map_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    u_char                      *p;
    u_char                      *script_path;
    ngx_str_t                   *value, name;
    ngx_http_variable_t         *var;
    ngx_http_lua_map_ctx_t      *ctx;

    value = cf->args->elts;
    name = value[1];
    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_map_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /* remove '$' */
    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->var = var;
    ctx->ref = LUA_REFNIL;
    var->data = (uintptr_t) ctx;

    if (cmd->post == ngx_http_lua_map_handler_file) {
        /* Lua code in an external file */

        script_path = ngx_http_lua_rebase_path(cf->pool, value[2].data,
                                        value[2].len);
        if (script_path == NULL) {
            return NGX_CONF_ERROR;
        }

        var->get_handler = ngx_http_lua_map_handler_file;
        ctx->script.data = script_path;
        ctx->script.len  = ngx_strlen(script_path);

        p = ngx_palloc(cf->pool, NGX_HTTP_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        ctx->script_key = p;

        p = ngx_copy(p, NGX_HTTP_LUA_FILE_TAG, NGX_HTTP_LUA_FILE_TAG_LEN);
        p = ngx_http_lua_digest_hex(p, value[2].data, value[2].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        var->get_handler = ngx_http_lua_map_handler_inline;
        ctx->script = value[2];

        p = ngx_palloc(cf->pool,
                       sizeof("map_by_lua") + NGX_HTTP_LUA_INLINE_KEY_LEN);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        ctx->script_key = p;

        p = ngx_copy(p, "map_by_lua", sizeof("map_by_lua") - 1);
        p = ngx_copy(p, NGX_HTTP_LUA_INLINE_TAG, NGX_HTTP_LUA_INLINE_TAG_LEN);
        p = ngx_http_lua_digest_hex(p, value[2].data, value[2].len);
        *p = '\0';
    }

    return NGX_CONF_OK;
}


char *
ngx_http_lua_map_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char        *rv;
    ngx_conf_t   save;

    save = *cf;
    cf->handler = ngx_http_lua_map_by_lua;
    cf->handler_conf = conf;

    rv = ngx_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


#ifndef NGX_LUA_NO_FFI_API


#endif  /* NGX_LUA_NO_FFI_API */
