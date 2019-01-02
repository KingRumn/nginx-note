
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_429)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_uint_t                       status;
    ngx_msec_t                       response_time;
    ngx_msec_t                       connect_time;
    ngx_msec_t                       header_time;
    off_t                            response_length;
    off_t                            bytes_received;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;

    unsigned                         down:1;
    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    /* ngx_http_upstream_t结构体中没有实现resolved成员时会用到；
     * 定义上游服务器的配置 */
    ngx_http_upstream_srv_conf_t    *upstream;

    /* 建立连接的超时时间 */
    ngx_msec_t                       connect_timeout;
    /* 发送请求的超时时间 */
    ngx_msec_t                       send_timeout;
    /* 接收响应的超时时间 */
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       next_upstream_timeout;

    /* TCP的SO_SNOLOWAT选项，表示发送缓冲区的下限 */
    size_t                           send_lowat;
    /* 定义了接收头部的缓冲区分配的内存大小---ngx_http_upstream_t->buffer
     * 如果不转发响应到下游或者在ngx_http_upstream_t->buffering=0时，同样表示接收包体的缓冲区大小*/
    size_t                           buffer_size;
    size_t                           limit_rate;

    /* 仅当ngx_http_upstream_t->buffering标志为1，且向下游转发响应时生效；
     * 会设置到ngx_event_t结构体的busy_size成员*/
    size_t                           busy_buffers_size;
    /* ngx_http_upstream_t->buffering=1:如果上游速度快于下游，可能将上游响应缓存到临时文件中，
     * 其指定了临时文件的最大长度；
     * 实际上，它将限制ngx_event_pipe_t->temp_file*/
    size_t                           max_temp_file_size;
    /* 将缓冲区的响应写入临时文件时一次写入字符流的最大长度 */
    size_t                           temp_file_write_size;

    /* 无意义 */
    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    /* ngx_http_upstream_t->buffering=1转发包体时所使用的内存大小 */
    ngx_bufs_t                       bufs;

    /* 解析完ngx_http_upsream_t->headers_in成员后，按照二进制位是的upstream在转发包体时可以跳过对某些头部的处理；
     * 作为32位整型，最多可以表示32个不需要处理的头部；
     * 当前仅仅使用9个，如NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT */
    ngx_uint_t                       ignore_headers;
    /* 以二进制来表示一些错误码，如果处理上游响应时发现这些错误码，
     * 那么在没有将请求转发给下游以前，选择下一个上有服务器重发请求 */
    ngx_uint_t                       next_upstream;
    /* buffering=1：可能把响应缓存到临时文件中
     * 在ngx_http_upstream_t->store=1时表示所创建目录、文件的权限 */
    ngx_uint_t                       store_access;
    ngx_uint_t                       next_upstream_tries;
    /* 这个和ngx_http_upsteam_t->buffering有什么关系?
     * 决定转发响应方式的标志位
     * buffering=1: 表示打开缓存，这时认为上游速度>下游， 尽量选择在内存或磁盘中缓存上游响应；
     * buffering=0: 仅仅会开辟一块固定大小的内存块作为缓存来转发响应;
     * 如果空间不够，可能出现无法处理上游请求的情况 */
    ngx_flag_t                       buffering;
    ngx_flag_t                       request_buffering;
    /* 无意义 */
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    /* 标志位：1表示与上游交互时不检查与下游之间的连接；
     * 即使下游客户端主动关闭了连接，也不会中断与上游服务器间的交互 */
    ngx_flag_t                       ignore_client_abort;
    /* 解析上游响应的包头时，如果解析后设置到headers_in的status_n错误码大于400，
     * 则会试图将之与error_page中指定的错误码匹配，如果匹配上，则发送指定的响应；
     * 否则继续返回上游服务器的错误码, 参见ngx_http_upstream_intercept_errors方法 */
    ngx_flag_t                       intercept_errors;
    /* buffering=1时才有意义，如果cyclic_temp_file为1，则会试图复用临时文件中使用过的空间。
     * 不建议设为1 */
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;

    /* buffering=1时，存放临时文件的路径 */
    ngx_path_t                      *temp_path;

    /* 不转发头部实际上是通过ngx_http_upstream_hide_headers_hash方法，
     * 根据hide_headers和pass_headers动态数组构造出的需要隐藏的HTTP头部散列表 */
    ngx_hash_t                       hide_headers_hash;
    /* 转发响应头部给下游客户端时，如果不希望转发某些头部，设置到hide_headers动态数组中 */
    ngx_array_t                     *hide_headers;
    /* 转发响应头部给下游客户端时，upstream_默认不转发如Date/Server之类的头部，如果确实希望直接转发，设置到这里 */
    ngx_array_t                     *pass_headers;

    /* 连接上游服务器时，使用的本机地址 */
    ngx_http_upstream_local_t       *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;
    ngx_flag_t                       cache_convert_head;
    ngx_flag_t                       cache_background_update;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *cache_purge;
    ngx_array_t                     *no_cache;
#endif

    /* ngx_http_upstream_t->store=1时，如果需要将上游的响应放到文件中，
     * store_lengths将表示存放路径的长度，
     * store_values表示存放路径 */
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
    /* 目前与ngx_http_upstream_t中的store相同 */
    signed                           store:2;
    /* intercept_errors的例外情况，1表示404会直接转发给下游，不去比较error_page */
    unsigned                         intercept_404:1;
    /* 1表示根据ngx_http_upstream_t中headers_in结构体里的X-Accel-Buffering头部来改变buffering标识为
     * 如为yes，buffering标志位为1。
     * 因此，change_buffering为1时将有可能根据上游服务器返回的响应头部，动态决定是否以上游网速优先
     * */
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif

    /* 使用upstream的模块名称，仅用于记录日志 */
    ngx_str_t                        module;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    /* 处理读事件的回调方法, 每个阶段的方法不同 */
    ngx_http_upstream_handler_pt     read_event_handler;
    /* 处理写事件的回调方法, 每个阶段的方法不同 */
    ngx_http_upstream_handler_pt     write_event_handler;

    /* 表示主动向上游发起的连接 */
    ngx_peer_connection_t            peer;

    /* 当向下有客户端转发响应时，
     * 如果打开了缓存，并且认为上游网速更快，则会使用pipe成员来转发响应；
     * 在使用这种方式转发响应时，必须由HTTP模块在使用upstream机制前构造pipe结构体，
     * 否则会coredump */
    ngx_event_pipe_t                *pipe;

    /* 所有需要发送到上游服务器的请求内容；
     * HTTP模块create_request回调方法就在于构造该链表*/
    ngx_chain_t                     *request_bufs;

    /* 定义了 向下有发送响应的方式 */
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    /* 使用upstream机制的各种配置;
     * 其指定了upstream的运行方式
     * 注意: 必须在启动upstream机制前，设置这些参数 */
    ngx_http_upstream_conf_t        *conf;

    ngx_http_upstream_srv_conf_t    *upstream;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

    /* HTTP模块在实现process_header方法时，
     * 如果希望upstream直接转发响应，就需要把解析出的响应头部适配为HTTP响应头部，
     * 同事需要把包头中的信息设置到headers_in结构体中，
     * 这样，后续步骤才会把这些头部添加到发送给下游客户端的响应头部headers_out中*/
    ngx_http_upstream_headers_in_t   headers_in;


    /* 用于解析主机域名 */
    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

    /* 接收上游服务器响应包头的缓冲区，
     * 在不需要把响应直接转发给客户端，或buffering标志位为0的情况下，接收包体的缓冲器仍然使用buffer；
     * 如果没有自定义input_filter方法处理包体，将会使用buffer存储全部的包体，这时的buffer必须足够大；
     * 它的大小由ngx_http_upstream_conf_t中的buffer_size成员决定 */
    ngx_buf_t                        buffer;
    /* 来自上游响应包体的长度 */
    off_t                            length;

    /* 1. 当不需要妆发包体，且使用默认的input_filter方法处理包体时
     *    out_bufs将会指向响应包体，事实上，out_bufs链表中会产生多个ngx_buf_t缓冲区，
     *    每个缓冲区都指向buffer缓存中的一部分；
     *    而这里的一部分就是每次调用recv方法接收到的一段tcp流；
     * 2. 当需要转发响应包体到下有时，（buffering标志为0，以下游网速优先），
     *    这个链表指向上一次向下游服务器转发响应到现在这段时间内接收自上游的缓存响应；
     *    */
    ngx_chain_t                     *out_bufs;

    /* 当需要转发包体到下游时（buffering=0），上一次向下游转发响应时没有发送玩的内容； */
    ngx_chain_t                     *busy_bufs;

    /* 用于回收out_bufs中已经发送给下游的ngx_buf_t结构体，
     * 同样应用于buffering=0的场景 */
    ngx_chain_t                     *free_bufs;

    /* 处理包体前的初始化方法，data用于传递参数 */
    ngx_int_t                      (*input_filter_init)(void *data);
    /* 处理包体的方法，data用于传递用户数据，实际上就是input_filter_ctx指针 */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    /* 用于传递HTTP模块自定义的数据结构，在input_filter_init和input_filter方法被回调时作为参数 */
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    /* HTTP模块自己实现，用于构造发往上游的服务器请求 */
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    /* 与上游通信失败后，如果按照重试规则还需要再次向服务器发送连接时调用 */
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    /* 解析上游服务器返回响应的包头，
     * 返回NGX_AGAIN表示包头没有接收完整
     * 返回NGX_HTTP_UPSTREAM_INVALID_HEADER表示包头不合法
     * 返回NGX_ERROR表示出现错误
     * 返回NGX_OK表示解析到完整的包头
     * */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    /* 当前版本无意义，均不会调用 */
    void                           (*abort_request)(ngx_http_request_t *r);
    /* 请求结束时调用 */
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    /* 上游响应出现Location或者Refresh头部表示重定向时，通过ngx_http_upstream_process_headers方法调用；
     * 由HTTP模块自己实现 */
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    /* 暂无意义 */
    ngx_msec_t                       timeout;

    /* 用于表示上游响应的错误码、包体、长度等信息 */
    ngx_http_upstream_state_t       *state;

    /* 不使用文件缓存时无意义 */
    ngx_str_t                        method;
    /* 在记录日志时会用到，此外无意义 */
    ngx_str_t                        schema;
    /* 在记录日志时会用到，此外无意义 */
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif

    /* 标志位，仅用于表示是否需要清理资源，实际不会调用到它所指的方法 */
    ngx_http_cleanup_pt             *cleanup;

    /* 是否指定文件缓存路径 */
    unsigned                         store:1;
    /* 是否用文件缓存 */
    unsigned                         cacheable:1;
    /* 暂无意义 */
    unsigned                         accel:1;
    /* 是否基于SSL访问上游服务器 */
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    /* 向下游转发上游的响应包体时，是否开启更大的内存及临时磁盘文件用于缓存来不及发送到下游的响应包体 */
    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;
    /* 1：确定与上游服务器的TCP连接建立成功, 但有可能出现异常断开;
     * 此时已经向上游发送了部分或全部请求，事实上，其更多地是为了使用ngx_output_chain方法，
     * 该方法会自动把未发送完的request_bufs记录下来，为了防止反复发送重复请求，request_sent标志记录是否调用过 */
    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    /* 将上游服务器的响应划分为包头和包尾，
     * 如果把响应直接转发给客户端，header_sent表示包头是否发送，
     * 如果不转发响应，无意义 */
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
