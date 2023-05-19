[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HASH_H_INCLUDED_
[9] #define _NGX_HASH_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     void             *value;
[18]     u_short           len;
[19]     u_char            name[1];
[20] } ngx_hash_elt_t;
[21] 
[22] 
[23] typedef struct {
[24]     ngx_hash_elt_t  **buckets;
[25]     ngx_uint_t        size;
[26] } ngx_hash_t;
[27] 
[28] 
[29] typedef struct {
[30]     ngx_hash_t        hash;
[31]     void             *value;
[32] } ngx_hash_wildcard_t;
[33] 
[34] 
[35] typedef struct {
[36]     ngx_str_t         key;
[37]     ngx_uint_t        key_hash;
[38]     void             *value;
[39] } ngx_hash_key_t;
[40] 
[41] 
[42] typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);
[43] 
[44] 
[45] typedef struct {
[46]     ngx_hash_t            hash;
[47]     ngx_hash_wildcard_t  *wc_head;
[48]     ngx_hash_wildcard_t  *wc_tail;
[49] } ngx_hash_combined_t;
[50] 
[51] 
[52] typedef struct {
[53]     ngx_hash_t       *hash;
[54]     ngx_hash_key_pt   key;
[55] 
[56]     ngx_uint_t        max_size;
[57]     ngx_uint_t        bucket_size;
[58] 
[59]     char             *name;
[60]     ngx_pool_t       *pool;
[61]     ngx_pool_t       *temp_pool;
[62] } ngx_hash_init_t;
[63] 
[64] 
[65] #define NGX_HASH_SMALL            1
[66] #define NGX_HASH_LARGE            2
[67] 
[68] #define NGX_HASH_LARGE_ASIZE      16384
[69] #define NGX_HASH_LARGE_HSIZE      10007
[70] 
[71] #define NGX_HASH_WILDCARD_KEY     1
[72] #define NGX_HASH_READONLY_KEY     2
[73] 
[74] 
[75] typedef struct {
[76]     ngx_uint_t        hsize;
[77] 
[78]     ngx_pool_t       *pool;
[79]     ngx_pool_t       *temp_pool;
[80] 
[81]     ngx_array_t       keys;
[82]     ngx_array_t      *keys_hash;
[83] 
[84]     ngx_array_t       dns_wc_head;
[85]     ngx_array_t      *dns_wc_head_hash;
[86] 
[87]     ngx_array_t       dns_wc_tail;
[88]     ngx_array_t      *dns_wc_tail_hash;
[89] } ngx_hash_keys_arrays_t;
[90] 
[91] 
[92] typedef struct ngx_table_elt_s  ngx_table_elt_t;
[93] 
[94] struct ngx_table_elt_s {
[95]     ngx_uint_t        hash;
[96]     ngx_str_t         key;
[97]     ngx_str_t         value;
[98]     u_char           *lowcase_key;
[99]     ngx_table_elt_t  *next;
[100] };
[101] 
[102] 
[103] void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
[104] void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
[105] void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
[106] void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
[107]     u_char *name, size_t len);
[108] 
[109] ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
[110]     ngx_uint_t nelts);
[111] ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
[112]     ngx_uint_t nelts);
[113] 
[114] #define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
[115] ngx_uint_t ngx_hash_key(u_char *data, size_t len);
[116] ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
[117] ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);
[118] 
[119] 
[120] ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
[121] ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
[122]     void *value, ngx_uint_t flags);
[123] 
[124] 
[125] #endif /* _NGX_HASH_H_INCLUDED_ */
