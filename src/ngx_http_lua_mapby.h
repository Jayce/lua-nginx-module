
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_MAP_H_INCLUDED_
#define _NGX_HTTP_LUA_MAP_H_INCLUDED_


#include "ngx_http_lua_common.h"


ngx_int_t ngx_http_lua_map_handler_inline(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_lua_map_handler_file(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

char *ngx_http_lua_map_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_lua_map_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


#endif /* _NGX_HTTP_LUA_MAP_H_INCLUDED_ */
