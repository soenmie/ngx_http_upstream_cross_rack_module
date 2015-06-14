/**
 * @file ngx_http_upstream_cross_seg_module.c
 * @author mian_sun(at)foxmail.com
 * @date 2015/06/01 10:20:30
 * @brief A cross segment uptream module for Nginx
 *
 **/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define CLASS_A_SUBNET_MASK 0xff000000
#define CLASS_B_SUBNET_MASK 0xffff0000
#define CLASS_C_SUBNET_MASK 0xffffff00

typedef struct ngx_http_upstream_cross_seg_dict_s ngx_http_upstream_cross_seg_dict_t;

struct ngx_http_upstream_cross_seg_dict_s {
    ngx_rbtree_t                       rbtree;
    ngx_rbtree_node_t                  sentinel;
    ngx_http_upstream_cross_seg_dict_t*  next;
};

typedef struct {
    ngx_http_upstream_cross_seg_dict_t   seg_dict;
} ngx_http_upstream_cross_seg_conf_t;

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;
    ngx_http_upstream_cross_seg_conf_t* conf;
} ngx_http_upstream_cross_seg_peer_data_t;

typedef struct {
    ngx_rbtree_node_t   rbtree_node;
    ngx_array_t*        ip_array;
} ngx_seg_rbtree_node_t;

static void* ngx_http_upstream_cross_seg_create_svr_conf(ngx_conf_t* cf);
static ngx_int_t ngx_http_upstream_cross_seg_add_ip(ngx_conf_t* cf,
        ngx_http_upstream_cross_seg_dict_t* seg_dict, ngx_uint_t ip, ngx_uint_t peer_idx);
static ngx_int_t ngx_http_upstream_init_cross_seg_peer(ngx_http_request_t* r,
        ngx_http_upstream_srv_conf_t* us);
static char* ngx_http_upstream_cross_seg(ngx_conf_t* cf, ngx_command_t* cmd,
        void* conf);
static ngx_int_t ngx_http_upstream_init_cross_seg(ngx_conf_t* cf,
        ngx_http_upstream_srv_conf_t* us);
static ngx_rbtree_node_t* ngx_rbtree_lookup(ngx_rbtree_t* rbtree,
        ngx_rbtree_node_t* sentinel, ngx_rbtree_key_t key);
static ngx_seg_rbtree_node_t* ngx_seg_rbtree_node_create(ngx_conf_t* cf,
        ngx_rbtree_key_t segment);
static ngx_int_t ngx_http_upstream_get_cross_seg_peer(ngx_peer_connection_t* pc,
        void* data);
static ngx_uint_t ngx_http_upstream_cross_seg_parse_ip(ngx_str_t* name);
static ngx_uint_t ngx_http_upstream_cross_seg_get_mask(ngx_uint_t ip);
/**
 * This module provided directive: cross_seq.
 *
 */
static ngx_command_t ngx_http_upstream_cross_seg_commands[] = {

    {
        ngx_string("cross_seg"), /* directive */
        NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS, /* upstream context and takes
                                            no arguments*/
        ngx_http_upstream_cross_seg, /* configuration setup function */
        0, /* No offset. Only one context is supported. */
        0, /* No offset when storing the module configuration on struct. */
        NULL
    },

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_upstream_cross_seg_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_upstream_cross_seg_create_svr_conf, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_upstream_cross_seg_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_cross_seg_module_ctx, /* module context */
    ngx_http_upstream_cross_seg_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static void*
ngx_http_upstream_cross_seg_create_svr_conf(ngx_conf_t* cf)
{
    ngx_http_upstream_cross_seg_conf_t* conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_cross_seg_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static ngx_rbtree_node_t*
ngx_rbtree_lookup(ngx_rbtree_t* rbtree, ngx_rbtree_node_t* sentinel,
                  ngx_rbtree_key_t key)
{
    ngx_rbtree_node_t* node = rbtree->root;
    while (node != sentinel) {
        if (key == node->key) {
            return node;
        }
        node = (key < node->key) ? node->left : node->right;
    }
    return NULL;
}

static ngx_seg_rbtree_node_t*
ngx_seg_rbtree_node_create(ngx_conf_t* cf, ngx_rbtree_key_t segment)
{
    ngx_seg_rbtree_node_t* node = ngx_pcalloc(cf->pool, sizeof(ngx_seg_rbtree_node_t));
    if (node == NULL) {
        return NULL;
    }
    node->rbtree_node.key = segment;
    node->ip_array = ngx_array_create(cf->pool, 1, sizeof(sizeof(ngx_uint_t)));
    if (node->ip_array == NULL) {
        return NULL;
    }
    return node;
}

static ngx_int_t
ngx_http_upstream_cross_seg_add_ip(ngx_conf_t* cf, ngx_http_upstream_cross_seg_dict_t* seg_dict,
                                   ngx_uint_t ip, ngx_uint_t peer_idx)
{
    ngx_uint_t                                mask, *peer_idx_ptr;
    ngx_rbtree_t*                             rbtree;
    ngx_rbtree_node_t*                        sentinel;
    ngx_seg_rbtree_node_t*                    node;
    mask = ngx_http_upstream_cross_seg_get_mask(ip);
    rbtree = &seg_dict->rbtree;
    sentinel = &seg_dict->sentinel;
    node = (ngx_seg_rbtree_node_t*)ngx_rbtree_lookup(rbtree, sentinel, ip & mask);
    if (node == NULL) {
        node = ngx_seg_rbtree_node_create(cf, ip & mask);
        if (node == NULL) {
            return NGX_ERROR;
        }
        ngx_rbtree_insert(rbtree, (ngx_rbtree_node_t*)node);
    }
    peer_idx_ptr = ngx_array_push(node->ip_array);
    if (peer_idx_ptr == NULL) {
        return NGX_ERROR;
    }
    *peer_idx_ptr  = ip;
    return NGX_OK;
}

/**
 * Content handler.
 *
 * @param cf
 *   Pointer to the configuration structure.
 * @param us
 *   Pointer to the upstream configuration structure.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t
ngx_http_upstream_init_cross_seg(ngx_conf_t* cf, ngx_http_upstream_srv_conf_t* us)
{
    ngx_uint_t                                i;
    ngx_http_upstream_rr_peers_t*             peers;
    ngx_http_upstream_cross_seg_conf_t*       conf;
    ngx_http_upstream_cross_seg_dict_t*       seg_dict;

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }
    us->peer.init = ngx_http_upstream_init_cross_seg_peer;
    peers = us->peer.data;

    conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_cross_seg_module);
    ngx_rbtree_init(&conf->seg_dict.rbtree, &conf->seg_dict.sentinel,
                    ngx_rbtree_insert_value);
    if (peers->next != NULL) {
        conf->seg_dict.next = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_cross_seg_dict_t));
        if (conf->seg_dict.next == NULL) {
            return NGX_ERROR;
        }
        ngx_rbtree_init(&conf->seg_dict.next->rbtree, &conf->seg_dict.next->sentinel,
                        ngx_rbtree_insert_value);
    }
    seg_dict = &conf->seg_dict;
    while (peers != NULL) {
        for (i = 0; i < peers->number; ++i) {
            // TODO check format, if domain, lookup ip
            ngx_uint_t ip = ngx_http_upstream_cross_seg_parse_ip(&peers->peer[i].name);
            if (ngx_http_upstream_cross_seg_add_ip(cf, seg_dict, ip, i) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        peers = peers->next;
        seg_dict = seg_dict->next;
    }
    return NGX_OK;
} /* ngx_http_upstream_init_cross_seg */

/**
 * ngx_http_upstream_init_cross_seg_peer
 *
 * @param r
 *   Pointer to the request structure.
 * @param us
 *   Pointer to the upstream configuration structure.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t
ngx_http_upstream_init_cross_seg_peer(ngx_http_request_t* r,
                                      ngx_http_upstream_srv_conf_t* us)
{
    ngx_http_upstream_cross_seg_peer_data_t* csp;
    ngx_http_upstream_cross_seg_conf_t* conf;
    csp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_cross_seg_peer_data_t));
    if (csp == NULL) {
        return NGX_ERROR;
    }
    r->upstream->peer.data = &csp->rrp;
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
    r->upstream->peer.get = ngx_http_upstream_get_cross_seg_peer;
    conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_cross_seg_module);
    csp->conf = conf;
    // TODO modify peer.tries
    // r->upstream->peer.tries = max_tries;
    return NGX_OK;
} /* ngx_http_upstream_init_cross_seg_peer */

static ngx_uint_t
ngx_http_upstream_cross_seg_parse_ip(ngx_str_t* name)
{
    ngx_uint_t i;
    ngx_uint_t shift = 32;
    ngx_uint_t byte = 0;
    ngx_uint_t ip = 0;
    for (i = 0; shift != 0; ++i) {
        if (i == name->len || name->data[i] < '0' || name->data[i] > '9') {
            shift -= 8;
            ip = (ip << shift) | byte;
            byte = 0;
        } else {
            byte = byte * 10 + name->data[i] - '0';
        }
    }
    return ip;
}

static ngx_uint_t
ngx_http_upstream_cross_seg_get_mask(ngx_uint_t ip)
{
    ngx_uint_t mask;
    if ((ip >> 24) < 128) {
        mask = CLASS_A_SUBNET_MASK;
    } else if ((ip >> 24) < 192) {
        mask = CLASS_B_SUBNET_MASK;
    } else {
        mask = CLASS_C_SUBNET_MASK;
    }
    return mask;
}

static ngx_int_t
ngx_http_upstream_get_cross_seg_peer(ngx_peer_connection_t* pc, void* data)
{
    ngx_uint_t                               i, m, n;
    ngx_int_t                                rc;
    ngx_str_t*                               name;
    ngx_uint_t                               ip, mask;
    ngx_http_upstream_cross_seg_peer_data_t* csp = data;
    ngx_http_upstream_cross_seg_dict_t*      seg_dict = &csp->conf->seg_dict;
    ngx_rbtree_t*                            rbtree = &seg_dict->rbtree;
    ngx_rbtree_node_t*                       sentinel = &seg_dict->sentinel;
    ngx_seg_rbtree_node_t*                   node;

    rc = ngx_http_upstream_get_round_robin_peer(pc, data);
    if (rc != NGX_OK) {
        return rc;
    }
    name = pc->name;
    ip = ngx_http_upstream_cross_seg_parse_ip(name);
    mask = ngx_http_upstream_cross_seg_get_mask(ip);
    node = (ngx_seg_rbtree_node_t*)ngx_rbtree_lookup(rbtree, sentinel, ip & mask);
    if (node == NULL) {
        rbtree = &seg_dict->next->rbtree;
        sentinel = &seg_dict->next->sentinel;
        node = (ngx_seg_rbtree_node_t*)ngx_rbtree_lookup(rbtree, sentinel, ip & mask);
        if (node == NULL) {
            return NGX_OK;
        }
    }
    for (i = 0; i < node->ip_array->nelts; ++i) {
        ngx_uint_t* peer_idx_ptr = (ngx_uint_t*)node->ip_array->elts + i;
        n = *peer_idx_ptr / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << *peer_idx_ptr % (8 * sizeof(uintptr_t));
        cps->rrp.tried[n] |= m;
    }
    return NGX_OK;
}
/**
 * Configuration setup function that installs the upstream handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char*
ngx_http_upstream_cross_seg(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_http_upstream_srv_conf_t*  uscf; /* pointer to uptream configuration */

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uscf->peer.init_upstream = ngx_http_upstream_init_cross_seg;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  | NGX_HTTP_UPSTREAM_WEIGHT
                  | NGX_HTTP_UPSTREAM_MAX_FAILS
                  | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  | NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
} /* ngx_http_upstream_cross_seg */

/* vim: set expandtab ts=4 sw=4 sts=4 tw=100: */
