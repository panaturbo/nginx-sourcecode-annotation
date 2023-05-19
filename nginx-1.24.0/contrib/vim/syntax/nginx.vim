[1] " Vim syntax file
[2] " Language: nginx.conf
[3] 
[4] if exists("b:current_syntax")
[5]   finish
[6] end
[7] 
[8] let s:save_cpo = &cpo
[9] set cpo&vim
[10] 
[11] " general syntax
[12] 
[13] if has("patch-7.4.1142")
[14]     " except control characters, ";", "{", and "}"
[15]     syn iskeyword 33-58,60-122,124,126-255
[16] endif
[17] 
[18] syn match ngxName '\([^;{} \t\\]\|\\.\)\+'
[19]     \ contains=@ngxDirectives
[20]     \ nextgroup=@ngxParams skipwhite skipempty
[21] syn match ngxParam '\(\${\|[^;{ \t\\]\|\\.\)\+'
[22]     \ contained
[23]     \ contains=ngxVariable
[24]     \ nextgroup=@ngxParams skipwhite skipempty
[25] syn region ngxString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+
[26]     \ contains=ngxVariableString
[27]     \ nextgroup=@ngxParams skipwhite skipempty
[28] syn match ngxParamComment '#.*$'
[29]     \ nextgroup=@ngxParams skipwhite skipempty
[30] syn match ngxSemicolon ';' contained
[31] syn region ngxBlock start=+{+ end=+}+ contained
[32]     \ contains=@ngxTopLevel
[33] syn match ngxComment '#.*$'
[34] 
[35] syn match ngxVariable '\$\(\w\+\|{\w\+}\)' contained
[36] syn match ngxVariableString '\$\(\w\+\|{\w\+}\)' contained
[37] 
[38] syn cluster ngxTopLevel
[39]     \ contains=ngxName,ngxString,ngxComment
[40] syn cluster ngxDirectives
[41]     \ contains=ngxDirective,ngxDirectiveBlock,ngxDirectiveImportant
[42]     \ add=ngxDirectiveControl,ngxDirectiveError,ngxDirectiveDeprecated
[43]     \ add=ngxDirectiveThirdParty,ngxDirectiveThirdPartyDeprecated
[44] syn cluster ngxParams
[45]     \ contains=ngxParam,ngxString,ngxParamComment,ngxSemicolon,ngxBlock
[46] 
[47] " boolean parameters
[48] 
[49] syn keyword ngxBoolean contained on off
[50]     \ nextgroup=@ngxParams skipwhite skipempty
[51] syn cluster ngxParams add=ngxBoolean
[52] 
[53] " listen directive
[54] 
[55] syn cluster ngxTopLevel add=ngxDirectiveListen
[56] syn keyword ngxDirectiveListen listen
[57]     \ nextgroup=@ngxListenParams skipwhite skipempty
[58] syn match ngxListenParam '\(\${\|[^;{ \t\\]\|\\.\)\+'
[59]     \ contained
[60]     \ nextgroup=@ngxListenParams skipwhite skipempty
[61] syn region ngxListenString start=+\z(["']\)+ end=+\z1+ skip=+\\\\\|\\\z1+
[62]     \ contained
[63]     \ nextgroup=@ngxListenParams skipwhite skipempty
[64] syn match ngxListenComment '#.*$'
[65]     \ contained
[66]     \ nextgroup=@ngxListenParams skipwhite skipempty
[67] syn keyword ngxListenOptions contained
[68]     \ default_server ssl http2 proxy_protocol
[69]     \ setfib fastopen backlog rcvbuf sndbuf accept_filter deferred bind
[70]     \ ipv6only reuseport so_keepalive
[71]     \ nextgroup=@ngxListenParams skipwhite skipempty
[72] syn keyword ngxListenOptionsDeprecated contained
[73]     \ spdy
[74]     \ nextgroup=@ngxListenParams skipwhite skipempty
[75] syn cluster ngxListenParams
[76]     \ contains=ngxListenParam,ngxListenString,ngxListenComment
[77]     \ add=ngxListenOptions,ngxListenOptionsDeprecated
[78] 
[79] syn keyword ngxDirectiveBlock contained http
[80] syn keyword ngxDirectiveBlock contained stream
[81] syn keyword ngxDirectiveBlock contained mail
[82] syn keyword ngxDirectiveBlock contained events
[83] syn keyword ngxDirectiveBlock contained server
[84] syn keyword ngxDirectiveBlock contained types
[85] syn keyword ngxDirectiveBlock contained location
[86] syn keyword ngxDirectiveBlock contained upstream
[87] syn keyword ngxDirectiveBlock contained charset_map
[88] syn keyword ngxDirectiveBlock contained limit_except
[89] syn keyword ngxDirectiveBlock contained if
[90] syn keyword ngxDirectiveBlock contained geo
[91] syn keyword ngxDirectiveBlock contained map
[92] syn keyword ngxDirectiveBlock contained split_clients
[93] syn keyword ngxDirectiveBlock contained match
[94] 
[95] syn keyword ngxDirectiveImportant contained include
[96] syn keyword ngxDirectiveImportant contained root
[97] syn keyword ngxDirectiveImportant contained server_name
[98] syn keyword ngxDirectiveImportant contained internal
[99] syn keyword ngxDirectiveImportant contained proxy_pass
[100] syn keyword ngxDirectiveImportant contained memcached_pass
[101] syn keyword ngxDirectiveImportant contained fastcgi_pass
[102] syn keyword ngxDirectiveImportant contained scgi_pass
[103] syn keyword ngxDirectiveImportant contained uwsgi_pass
[104] syn keyword ngxDirectiveImportant contained try_files
[105] 
[106] syn keyword ngxDirectiveControl contained break
[107] syn keyword ngxDirectiveControl contained return
[108] syn keyword ngxDirectiveControl contained rewrite
[109] syn keyword ngxDirectiveControl contained set
[110] 
[111] syn keyword ngxDirectiveError contained error_page
[112] syn keyword ngxDirectiveError contained post_action
[113] 
[114] syn keyword ngxDirectiveDeprecated contained proxy_downstream_buffer
[115] syn keyword ngxDirectiveDeprecated contained proxy_upstream_buffer
[116] syn keyword ngxDirectiveDeprecated contained ssl
[117] syn keyword ngxDirectiveDeprecated contained http2_idle_timeout
[118] syn keyword ngxDirectiveDeprecated contained http2_max_field_size
[119] syn keyword ngxDirectiveDeprecated contained http2_max_header_size
[120] syn keyword ngxDirectiveDeprecated contained http2_max_requests
[121] syn keyword ngxDirectiveDeprecated contained http2_recv_timeout
[122] 
[123] syn keyword ngxDirective contained absolute_redirect
[124] syn keyword ngxDirective contained accept_mutex
[125] syn keyword ngxDirective contained accept_mutex_delay
[126] syn keyword ngxDirective contained acceptex_read
[127] syn keyword ngxDirective contained access_log
[128] syn keyword ngxDirective contained add_after_body
[129] syn keyword ngxDirective contained add_before_body
[130] syn keyword ngxDirective contained add_header
[131] syn keyword ngxDirective contained add_trailer
[132] syn keyword ngxDirective contained addition_types
[133] syn keyword ngxDirective contained aio
[134] syn keyword ngxDirective contained aio_write
[135] syn keyword ngxDirective contained alias
[136] syn keyword ngxDirective contained allow
[137] syn keyword ngxDirective contained ancient_browser
[138] syn keyword ngxDirective contained ancient_browser_value
[139] syn keyword ngxDirective contained api
[140] syn keyword ngxDirective contained auth_basic
[141] syn keyword ngxDirective contained auth_basic_user_file
[142] syn keyword ngxDirective contained auth_delay
[143] syn keyword ngxDirective contained auth_http
[144] syn keyword ngxDirective contained auth_http_header
[145] syn keyword ngxDirective contained auth_http_pass_client_cert
[146] syn keyword ngxDirective contained auth_http_timeout
[147] syn keyword ngxDirective contained auth_jwt
[148] syn keyword ngxDirective contained auth_jwt_claim_set
[149] syn keyword ngxDirective contained auth_jwt_header_set
[150] syn keyword ngxDirective contained auth_jwt_key_cache
[151] syn keyword ngxDirective contained auth_jwt_key_file
[152] syn keyword ngxDirective contained auth_jwt_key_request
[153] syn keyword ngxDirective contained auth_jwt_leeway
[154] syn keyword ngxDirective contained auth_jwt_require
[155] syn keyword ngxDirective contained auth_jwt_type
[156] syn keyword ngxDirective contained auth_request
[157] syn keyword ngxDirective contained auth_request_set
[158] syn keyword ngxDirective contained autoindex
[159] syn keyword ngxDirective contained autoindex_exact_size
[160] syn keyword ngxDirective contained autoindex_format
[161] syn keyword ngxDirective contained autoindex_localtime
[162] syn keyword ngxDirective contained charset
[163] syn keyword ngxDirective contained charset_types
[164] syn keyword ngxDirective contained chunked_transfer_encoding
[165] syn keyword ngxDirective contained client_body_buffer_size
[166] syn keyword ngxDirective contained client_body_in_file_only
[167] syn keyword ngxDirective contained client_body_in_single_buffer
[168] syn keyword ngxDirective contained client_body_temp_path
[169] syn keyword ngxDirective contained client_body_timeout
[170] syn keyword ngxDirective contained client_header_buffer_size
[171] syn keyword ngxDirective contained client_header_timeout
[172] syn keyword ngxDirective contained client_max_body_size
[173] syn keyword ngxDirective contained connection_pool_size
[174] syn keyword ngxDirective contained create_full_put_path
[175] syn keyword ngxDirective contained daemon
[176] syn keyword ngxDirective contained dav_access
[177] syn keyword ngxDirective contained dav_methods
[178] syn keyword ngxDirective contained debug_connection
[179] syn keyword ngxDirective contained debug_points
[180] syn keyword ngxDirective contained default_type
[181] syn keyword ngxDirective contained degradation
[182] syn keyword ngxDirective contained degrade
[183] syn keyword ngxDirective contained deny
[184] syn keyword ngxDirective contained devpoll_changes
[185] syn keyword ngxDirective contained devpoll_events
[186] syn keyword ngxDirective contained directio
[187] syn keyword ngxDirective contained directio_alignment
[188] syn keyword ngxDirective contained disable_symlinks
[189] syn keyword ngxDirective contained empty_gif
[190] syn keyword ngxDirective contained env
[191] syn keyword ngxDirective contained epoll_events
[192] syn keyword ngxDirective contained error_log
[193] syn keyword ngxDirective contained etag
[194] syn keyword ngxDirective contained eventport_events
[195] syn keyword ngxDirective contained expires
[196] syn keyword ngxDirective contained f4f
[197] syn keyword ngxDirective contained f4f_buffer_size
[198] syn keyword ngxDirective contained fastcgi_bind
[199] syn keyword ngxDirective contained fastcgi_buffer_size
[200] syn keyword ngxDirective contained fastcgi_buffering
[201] syn keyword ngxDirective contained fastcgi_buffers
[202] syn keyword ngxDirective contained fastcgi_busy_buffers_size
[203] syn keyword ngxDirective contained fastcgi_cache
[204] syn keyword ngxDirective contained fastcgi_cache_background_update
[205] syn keyword ngxDirective contained fastcgi_cache_bypass
[206] syn keyword ngxDirective contained fastcgi_cache_key
[207] syn keyword ngxDirective contained fastcgi_cache_lock
[208] syn keyword ngxDirective contained fastcgi_cache_lock_age
[209] syn keyword ngxDirective contained fastcgi_cache_lock_timeout
[210] syn keyword ngxDirective contained fastcgi_cache_max_range_offset
[211] syn keyword ngxDirective contained fastcgi_cache_methods
[212] syn keyword ngxDirective contained fastcgi_cache_min_uses
[213] syn keyword ngxDirective contained fastcgi_cache_path
[214] syn keyword ngxDirective contained fastcgi_cache_purge
[215] syn keyword ngxDirective contained fastcgi_cache_revalidate
[216] syn keyword ngxDirective contained fastcgi_cache_use_stale
[217] syn keyword ngxDirective contained fastcgi_cache_valid
[218] syn keyword ngxDirective contained fastcgi_catch_stderr
[219] syn keyword ngxDirective contained fastcgi_connect_timeout
[220] syn keyword ngxDirective contained fastcgi_force_ranges
[221] syn keyword ngxDirective contained fastcgi_hide_header
[222] syn keyword ngxDirective contained fastcgi_ignore_client_abort
[223] syn keyword ngxDirective contained fastcgi_ignore_headers
[224] syn keyword ngxDirective contained fastcgi_index
[225] syn keyword ngxDirective contained fastcgi_intercept_errors
[226] syn keyword ngxDirective contained fastcgi_keep_conn
[227] syn keyword ngxDirective contained fastcgi_limit_rate
[228] syn keyword ngxDirective contained fastcgi_max_temp_file_size
[229] syn keyword ngxDirective contained fastcgi_next_upstream
[230] syn keyword ngxDirective contained fastcgi_next_upstream_timeout
[231] syn keyword ngxDirective contained fastcgi_next_upstream_tries
[232] syn keyword ngxDirective contained fastcgi_no_cache
[233] syn keyword ngxDirective contained fastcgi_param
[234] syn keyword ngxDirective contained fastcgi_pass_header
[235] syn keyword ngxDirective contained fastcgi_pass_request_body
[236] syn keyword ngxDirective contained fastcgi_pass_request_headers
[237] syn keyword ngxDirective contained fastcgi_read_timeout
[238] syn keyword ngxDirective contained fastcgi_request_buffering
[239] syn keyword ngxDirective contained fastcgi_send_lowat
[240] syn keyword ngxDirective contained fastcgi_send_timeout
[241] syn keyword ngxDirective contained fastcgi_socket_keepalive
[242] syn keyword ngxDirective contained fastcgi_split_path_info
[243] syn keyword ngxDirective contained fastcgi_store
[244] syn keyword ngxDirective contained fastcgi_store_access
[245] syn keyword ngxDirective contained fastcgi_temp_file_write_size
[246] syn keyword ngxDirective contained fastcgi_temp_path
[247] syn keyword ngxDirective contained flv
[248] syn keyword ngxDirective contained geoip_city
[249] syn keyword ngxDirective contained geoip_country
[250] syn keyword ngxDirective contained geoip_org
[251] syn keyword ngxDirective contained geoip_proxy
[252] syn keyword ngxDirective contained geoip_proxy_recursive
[253] syn keyword ngxDirective contained google_perftools_profiles
[254] syn keyword ngxDirective contained grpc_bind
[255] syn keyword ngxDirective contained grpc_buffer_size
[256] syn keyword ngxDirective contained grpc_connect_timeout
[257] syn keyword ngxDirective contained grpc_hide_header
[258] syn keyword ngxDirective contained grpc_ignore_headers
[259] syn keyword ngxDirective contained grpc_intercept_errors
[260] syn keyword ngxDirective contained grpc_next_upstream
[261] syn keyword ngxDirective contained grpc_next_upstream_timeout
[262] syn keyword ngxDirective contained grpc_next_upstream_tries
[263] syn keyword ngxDirective contained grpc_pass
[264] syn keyword ngxDirective contained grpc_pass_header
[265] syn keyword ngxDirective contained grpc_read_timeout
[266] syn keyword ngxDirective contained grpc_send_timeout
[267] syn keyword ngxDirective contained grpc_set_header
[268] syn keyword ngxDirective contained grpc_socket_keepalive
[269] syn keyword ngxDirective contained grpc_ssl_certificate
[270] syn keyword ngxDirective contained grpc_ssl_certificate_key
[271] syn keyword ngxDirective contained grpc_ssl_ciphers
[272] syn keyword ngxDirective contained grpc_ssl_conf_command
[273] syn keyword ngxDirective contained grpc_ssl_crl
[274] syn keyword ngxDirective contained grpc_ssl_name
[275] syn keyword ngxDirective contained grpc_ssl_password_file
[276] syn keyword ngxDirective contained grpc_ssl_protocols
[277] syn keyword ngxDirective contained grpc_ssl_server_name
[278] syn keyword ngxDirective contained grpc_ssl_session_reuse
[279] syn keyword ngxDirective contained grpc_ssl_trusted_certificate
[280] syn keyword ngxDirective contained grpc_ssl_verify
[281] syn keyword ngxDirective contained grpc_ssl_verify_depth
[282] syn keyword ngxDirective contained gunzip
[283] syn keyword ngxDirective contained gunzip_buffers
[284] syn keyword ngxDirective contained gzip
[285] syn keyword ngxDirective contained gzip_buffers
[286] syn keyword ngxDirective contained gzip_comp_level
[287] syn keyword ngxDirective contained gzip_disable
[288] syn keyword ngxDirective contained gzip_hash
[289] syn keyword ngxDirective contained gzip_http_version
[290] syn keyword ngxDirective contained gzip_min_length
[291] syn keyword ngxDirective contained gzip_no_buffer
[292] syn keyword ngxDirective contained gzip_proxied
[293] syn keyword ngxDirective contained gzip_static
[294] syn keyword ngxDirective contained gzip_types
[295] syn keyword ngxDirective contained gzip_vary
[296] syn keyword ngxDirective contained gzip_window
[297] syn keyword ngxDirective contained hash
[298] syn keyword ngxDirective contained health_check
[299] syn keyword ngxDirective contained health_check_timeout
[300] syn keyword ngxDirective contained hls
[301] syn keyword ngxDirective contained hls_buffers
[302] syn keyword ngxDirective contained hls_forward_args
[303] syn keyword ngxDirective contained hls_fragment
[304] syn keyword ngxDirective contained hls_mp4_buffer_size
[305] syn keyword ngxDirective contained hls_mp4_max_buffer_size
[306] syn keyword ngxDirective contained http2_body_preread_size
[307] syn keyword ngxDirective contained http2_chunk_size
[308] syn keyword ngxDirective contained http2_max_concurrent_pushes
[309] syn keyword ngxDirective contained http2_max_concurrent_streams
[310] syn keyword ngxDirective contained http2_pool_size
[311] syn keyword ngxDirective contained http2_push
[312] syn keyword ngxDirective contained http2_push_preload
[313] syn keyword ngxDirective contained http2_recv_buffer_size
[314] syn keyword ngxDirective contained http2_streams_index_size
[315] syn keyword ngxDirective contained if_modified_since
[316] syn keyword ngxDirective contained ignore_invalid_headers
[317] syn keyword ngxDirective contained image_filter
[318] syn keyword ngxDirective contained image_filter_buffer
[319] syn keyword ngxDirective contained image_filter_interlace
[320] syn keyword ngxDirective contained image_filter_jpeg_quality
[321] syn keyword ngxDirective contained image_filter_sharpen
[322] syn keyword ngxDirective contained image_filter_transparency
[323] syn keyword ngxDirective contained image_filter_webp_quality
[324] syn keyword ngxDirective contained imap_auth
[325] syn keyword ngxDirective contained imap_capabilities
[326] syn keyword ngxDirective contained imap_client_buffer
[327] syn keyword ngxDirective contained index
[328] syn keyword ngxDirective contained iocp_threads
[329] syn keyword ngxDirective contained ip_hash
[330] syn keyword ngxDirective contained js_access
[331] syn keyword ngxDirective contained js_body_filter
[332] syn keyword ngxDirective contained js_content
[333] syn keyword ngxDirective contained js_fetch_buffer_size
[334] syn keyword ngxDirective contained js_fetch_ciphers
[335] syn keyword ngxDirective contained js_fetch_max_response_buffer_size
[336] syn keyword ngxDirective contained js_fetch_protocols
[337] syn keyword ngxDirective contained js_fetch_timeout
[338] syn keyword ngxDirective contained js_fetch_trusted_certificate
[339] syn keyword ngxDirective contained js_fetch_verify
[340] syn keyword ngxDirective contained js_fetch_verify_depth
[341] syn keyword ngxDirective contained js_filter
[342] syn keyword ngxDirective contained js_header_filter
[343] syn keyword ngxDirective contained js_import
[344] syn keyword ngxDirective contained js_path
[345] syn keyword ngxDirective contained js_preread
[346] syn keyword ngxDirective contained js_set
[347] syn keyword ngxDirective contained js_var
[348] syn keyword ngxDirective contained keepalive
[349] syn keyword ngxDirective contained keepalive_disable
[350] syn keyword ngxDirective contained keepalive_requests
[351] syn keyword ngxDirective contained keepalive_time
[352] syn keyword ngxDirective contained keepalive_timeout
[353] syn keyword ngxDirective contained keyval
[354] syn keyword ngxDirective contained keyval_zone
[355] syn keyword ngxDirective contained kqueue_changes
[356] syn keyword ngxDirective contained kqueue_events
[357] syn keyword ngxDirective contained large_client_header_buffers
[358] syn keyword ngxDirective contained least_conn
[359] syn keyword ngxDirective contained least_time
[360] syn keyword ngxDirective contained limit_conn
[361] syn keyword ngxDirective contained limit_conn_dry_run
[362] syn keyword ngxDirective contained limit_conn_log_level
[363] syn keyword ngxDirective contained limit_conn_status
[364] syn keyword ngxDirective contained limit_conn_zone
[365] syn keyword ngxDirective contained limit_rate
[366] syn keyword ngxDirective contained limit_rate_after
[367] syn keyword ngxDirective contained limit_req
[368] syn keyword ngxDirective contained limit_req_dry_run
[369] syn keyword ngxDirective contained limit_req_log_level
[370] syn keyword ngxDirective contained limit_req_status
[371] syn keyword ngxDirective contained limit_req_zone
[372] syn keyword ngxDirective contained lingering_close
[373] syn keyword ngxDirective contained lingering_time
[374] syn keyword ngxDirective contained lingering_timeout
[375] syn keyword ngxDirective contained load_module
[376] syn keyword ngxDirective contained lock_file
[377] syn keyword ngxDirective contained log_format
[378] syn keyword ngxDirective contained log_not_found
[379] syn keyword ngxDirective contained log_subrequest
[380] syn keyword ngxDirective contained map_hash_bucket_size
[381] syn keyword ngxDirective contained map_hash_max_size
[382] syn keyword ngxDirective contained master_process
[383] syn keyword ngxDirective contained max_errors
[384] syn keyword ngxDirective contained max_ranges
[385] syn keyword ngxDirective contained memcached_bind
[386] syn keyword ngxDirective contained memcached_buffer_size
[387] syn keyword ngxDirective contained memcached_connect_timeout
[388] syn keyword ngxDirective contained memcached_gzip_flag
[389] syn keyword ngxDirective contained memcached_next_upstream
[390] syn keyword ngxDirective contained memcached_next_upstream_timeout
[391] syn keyword ngxDirective contained memcached_next_upstream_tries
[392] syn keyword ngxDirective contained memcached_read_timeout
[393] syn keyword ngxDirective contained memcached_send_timeout
[394] syn keyword ngxDirective contained memcached_socket_keepalive
[395] syn keyword ngxDirective contained merge_slashes
[396] syn keyword ngxDirective contained min_delete_depth
[397] syn keyword ngxDirective contained mirror
[398] syn keyword ngxDirective contained mirror_request_body
[399] syn keyword ngxDirective contained modern_browser
[400] syn keyword ngxDirective contained modern_browser_value
[401] syn keyword ngxDirective contained mp4
[402] syn keyword ngxDirective contained mp4_buffer_size
[403] syn keyword ngxDirective contained mp4_limit_rate
[404] syn keyword ngxDirective contained mp4_limit_rate_after
[405] syn keyword ngxDirective contained mp4_max_buffer_size
[406] syn keyword ngxDirective contained mp4_start_key_frame
[407] syn keyword ngxDirective contained msie_padding
[408] syn keyword ngxDirective contained msie_refresh
[409] syn keyword ngxDirective contained multi_accept
[410] syn keyword ngxDirective contained ntlm
[411] syn keyword ngxDirective contained open_file_cache
[412] syn keyword ngxDirective contained open_file_cache_errors
[413] syn keyword ngxDirective contained open_file_cache_events
[414] syn keyword ngxDirective contained open_file_cache_min_uses
[415] syn keyword ngxDirective contained open_file_cache_valid
[416] syn keyword ngxDirective contained open_log_file_cache
[417] syn keyword ngxDirective contained output_buffers
[418] syn keyword ngxDirective contained override_charset
[419] syn keyword ngxDirective contained pcre_jit
[420] syn keyword ngxDirective contained perl
[421] syn keyword ngxDirective contained perl_modules
[422] syn keyword ngxDirective contained perl_require
[423] syn keyword ngxDirective contained perl_set
[424] syn keyword ngxDirective contained pid
[425] syn keyword ngxDirective contained pop3_auth
[426] syn keyword ngxDirective contained pop3_capabilities
[427] syn keyword ngxDirective contained port_in_redirect
[428] syn keyword ngxDirective contained post_acceptex
[429] syn keyword ngxDirective contained postpone_gzipping
[430] syn keyword ngxDirective contained postpone_output
[431] syn keyword ngxDirective contained preread_buffer_size
[432] syn keyword ngxDirective contained preread_timeout
[433] syn keyword ngxDirective contained protocol
[434] syn keyword ngxDirective contained proxy
[435] syn keyword ngxDirective contained proxy_bind
[436] syn keyword ngxDirective contained proxy_buffer
[437] syn keyword ngxDirective contained proxy_buffer_size
[438] syn keyword ngxDirective contained proxy_buffering
[439] syn keyword ngxDirective contained proxy_buffers
[440] syn keyword ngxDirective contained proxy_busy_buffers_size
[441] syn keyword ngxDirective contained proxy_cache
[442] syn keyword ngxDirective contained proxy_cache_background_update
[443] syn keyword ngxDirective contained proxy_cache_bypass
[444] syn keyword ngxDirective contained proxy_cache_convert_head
[445] syn keyword ngxDirective contained proxy_cache_key
[446] syn keyword ngxDirective contained proxy_cache_lock
[447] syn keyword ngxDirective contained proxy_cache_lock_age
[448] syn keyword ngxDirective contained proxy_cache_lock_timeout
[449] syn keyword ngxDirective contained proxy_cache_max_range_offset
[450] syn keyword ngxDirective contained proxy_cache_methods
[451] syn keyword ngxDirective contained proxy_cache_min_uses
[452] syn keyword ngxDirective contained proxy_cache_path
[453] syn keyword ngxDirective contained proxy_cache_purge
[454] syn keyword ngxDirective contained proxy_cache_revalidate
[455] syn keyword ngxDirective contained proxy_cache_use_stale
[456] syn keyword ngxDirective contained proxy_cache_valid
[457] syn keyword ngxDirective contained proxy_connect_timeout
[458] syn keyword ngxDirective contained proxy_cookie_domain
[459] syn keyword ngxDirective contained proxy_cookie_flags
[460] syn keyword ngxDirective contained proxy_cookie_path
[461] syn keyword ngxDirective contained proxy_download_rate
[462] syn keyword ngxDirective contained proxy_force_ranges
[463] syn keyword ngxDirective contained proxy_half_close
[464] syn keyword ngxDirective contained proxy_headers_hash_bucket_size
[465] syn keyword ngxDirective contained proxy_headers_hash_max_size
[466] syn keyword ngxDirective contained proxy_hide_header
[467] syn keyword ngxDirective contained proxy_http_version
[468] syn keyword ngxDirective contained proxy_ignore_client_abort
[469] syn keyword ngxDirective contained proxy_ignore_headers
[470] syn keyword ngxDirective contained proxy_intercept_errors
[471] syn keyword ngxDirective contained proxy_limit_rate
[472] syn keyword ngxDirective contained proxy_max_temp_file_size
[473] syn keyword ngxDirective contained proxy_method
[474] syn keyword ngxDirective contained proxy_next_upstream
[475] syn keyword ngxDirective contained proxy_next_upstream_timeout
[476] syn keyword ngxDirective contained proxy_next_upstream_tries
[477] syn keyword ngxDirective contained proxy_no_cache
[478] syn keyword ngxDirective contained proxy_pass_error_message
[479] syn keyword ngxDirective contained proxy_pass_header
[480] syn keyword ngxDirective contained proxy_pass_request_body
[481] syn keyword ngxDirective contained proxy_pass_request_headers
[482] syn keyword ngxDirective contained proxy_protocol
[483] syn keyword ngxDirective contained proxy_protocol_timeout
[484] syn keyword ngxDirective contained proxy_read_timeout
[485] syn keyword ngxDirective contained proxy_redirect
[486] syn keyword ngxDirective contained proxy_request_buffering
[487] syn keyword ngxDirective contained proxy_requests
[488] syn keyword ngxDirective contained proxy_responses
[489] syn keyword ngxDirective contained proxy_send_lowat
[490] syn keyword ngxDirective contained proxy_send_timeout
[491] syn keyword ngxDirective contained proxy_session_drop
[492] syn keyword ngxDirective contained proxy_set_body
[493] syn keyword ngxDirective contained proxy_set_header
[494] syn keyword ngxDirective contained proxy_smtp_auth
[495] syn keyword ngxDirective contained proxy_socket_keepalive
[496] syn keyword ngxDirective contained proxy_ssl
[497] syn keyword ngxDirective contained proxy_ssl_certificate
[498] syn keyword ngxDirective contained proxy_ssl_certificate_key
[499] syn keyword ngxDirective contained proxy_ssl_ciphers
[500] syn keyword ngxDirective contained proxy_ssl_conf_command
[501] syn keyword ngxDirective contained proxy_ssl_crl
[502] syn keyword ngxDirective contained proxy_ssl_name
[503] syn keyword ngxDirective contained proxy_ssl_password_file
[504] syn keyword ngxDirective contained proxy_ssl_protocols
[505] syn keyword ngxDirective contained proxy_ssl_server_name
[506] syn keyword ngxDirective contained proxy_ssl_session_reuse
[507] syn keyword ngxDirective contained proxy_ssl_trusted_certificate
[508] syn keyword ngxDirective contained proxy_ssl_verify
[509] syn keyword ngxDirective contained proxy_ssl_verify_depth
[510] syn keyword ngxDirective contained proxy_store
[511] syn keyword ngxDirective contained proxy_store_access
[512] syn keyword ngxDirective contained proxy_temp_file_write_size
[513] syn keyword ngxDirective contained proxy_temp_path
[514] syn keyword ngxDirective contained proxy_timeout
[515] syn keyword ngxDirective contained proxy_upload_rate
[516] syn keyword ngxDirective contained queue
[517] syn keyword ngxDirective contained random
[518] syn keyword ngxDirective contained random_index
[519] syn keyword ngxDirective contained read_ahead
[520] syn keyword ngxDirective contained real_ip_header
[521] syn keyword ngxDirective contained real_ip_recursive
[522] syn keyword ngxDirective contained recursive_error_pages
[523] syn keyword ngxDirective contained referer_hash_bucket_size
[524] syn keyword ngxDirective contained referer_hash_max_size
[525] syn keyword ngxDirective contained request_pool_size
[526] syn keyword ngxDirective contained reset_timedout_connection
[527] syn keyword ngxDirective contained resolver
[528] syn keyword ngxDirective contained resolver_timeout
[529] syn keyword ngxDirective contained rewrite_log
[530] syn keyword ngxDirective contained satisfy
[531] syn keyword ngxDirective contained scgi_bind
[532] syn keyword ngxDirective contained scgi_buffer_size
[533] syn keyword ngxDirective contained scgi_buffering
[534] syn keyword ngxDirective contained scgi_buffers
[535] syn keyword ngxDirective contained scgi_busy_buffers_size
[536] syn keyword ngxDirective contained scgi_cache
[537] syn keyword ngxDirective contained scgi_cache_background_update
[538] syn keyword ngxDirective contained scgi_cache_bypass
[539] syn keyword ngxDirective contained scgi_cache_key
[540] syn keyword ngxDirective contained scgi_cache_lock
[541] syn keyword ngxDirective contained scgi_cache_lock_age
[542] syn keyword ngxDirective contained scgi_cache_lock_timeout
[543] syn keyword ngxDirective contained scgi_cache_max_range_offset
[544] syn keyword ngxDirective contained scgi_cache_methods
[545] syn keyword ngxDirective contained scgi_cache_min_uses
[546] syn keyword ngxDirective contained scgi_cache_path
[547] syn keyword ngxDirective contained scgi_cache_purge
[548] syn keyword ngxDirective contained scgi_cache_revalidate
[549] syn keyword ngxDirective contained scgi_cache_use_stale
[550] syn keyword ngxDirective contained scgi_cache_valid
[551] syn keyword ngxDirective contained scgi_connect_timeout
[552] syn keyword ngxDirective contained scgi_force_ranges
[553] syn keyword ngxDirective contained scgi_hide_header
[554] syn keyword ngxDirective contained scgi_ignore_client_abort
[555] syn keyword ngxDirective contained scgi_ignore_headers
[556] syn keyword ngxDirective contained scgi_intercept_errors
[557] syn keyword ngxDirective contained scgi_limit_rate
[558] syn keyword ngxDirective contained scgi_max_temp_file_size
[559] syn keyword ngxDirective contained scgi_next_upstream
[560] syn keyword ngxDirective contained scgi_next_upstream_timeout
[561] syn keyword ngxDirective contained scgi_next_upstream_tries
[562] syn keyword ngxDirective contained scgi_no_cache
[563] syn keyword ngxDirective contained scgi_param
[564] syn keyword ngxDirective contained scgi_pass_header
[565] syn keyword ngxDirective contained scgi_pass_request_body
[566] syn keyword ngxDirective contained scgi_pass_request_headers
[567] syn keyword ngxDirective contained scgi_read_timeout
[568] syn keyword ngxDirective contained scgi_request_buffering
[569] syn keyword ngxDirective contained scgi_send_timeout
[570] syn keyword ngxDirective contained scgi_socket_keepalive
[571] syn keyword ngxDirective contained scgi_store
[572] syn keyword ngxDirective contained scgi_store_access
[573] syn keyword ngxDirective contained scgi_temp_file_write_size
[574] syn keyword ngxDirective contained scgi_temp_path
[575] syn keyword ngxDirective contained secure_link
[576] syn keyword ngxDirective contained secure_link_md5
[577] syn keyword ngxDirective contained secure_link_secret
[578] syn keyword ngxDirective contained send_lowat
[579] syn keyword ngxDirective contained send_timeout
[580] syn keyword ngxDirective contained sendfile
[581] syn keyword ngxDirective contained sendfile_max_chunk
[582] syn keyword ngxDirective contained server_name_in_redirect
[583] syn keyword ngxDirective contained server_names_hash_bucket_size
[584] syn keyword ngxDirective contained server_names_hash_max_size
[585] syn keyword ngxDirective contained server_tokens
[586] syn keyword ngxDirective contained session_log
[587] syn keyword ngxDirective contained session_log_format
[588] syn keyword ngxDirective contained session_log_zone
[589] syn keyword ngxDirective contained set_real_ip_from
[590] syn keyword ngxDirective contained slice
[591] syn keyword ngxDirective contained smtp_auth
[592] syn keyword ngxDirective contained smtp_capabilities
[593] syn keyword ngxDirective contained smtp_client_buffer
[594] syn keyword ngxDirective contained smtp_greeting_delay
[595] syn keyword ngxDirective contained source_charset
[596] syn keyword ngxDirective contained ssi
[597] syn keyword ngxDirective contained ssi_ignore_recycled_buffers
[598] syn keyword ngxDirective contained ssi_last_modified
[599] syn keyword ngxDirective contained ssi_min_file_chunk
[600] syn keyword ngxDirective contained ssi_silent_errors
[601] syn keyword ngxDirective contained ssi_types
[602] syn keyword ngxDirective contained ssi_value_length
[603] syn keyword ngxDirective contained ssl_alpn
[604] syn keyword ngxDirective contained ssl_buffer_size
[605] syn keyword ngxDirective contained ssl_certificate
[606] syn keyword ngxDirective contained ssl_certificate_key
[607] syn keyword ngxDirective contained ssl_ciphers
[608] syn keyword ngxDirective contained ssl_client_certificate
[609] syn keyword ngxDirective contained ssl_conf_command
[610] syn keyword ngxDirective contained ssl_crl
[611] syn keyword ngxDirective contained ssl_dhparam
[612] syn keyword ngxDirective contained ssl_early_data
[613] syn keyword ngxDirective contained ssl_ecdh_curve
[614] syn keyword ngxDirective contained ssl_engine
[615] syn keyword ngxDirective contained ssl_handshake_timeout
[616] syn keyword ngxDirective contained ssl_ocsp
[617] syn keyword ngxDirective contained ssl_ocsp_cache
[618] syn keyword ngxDirective contained ssl_ocsp_responder
[619] syn keyword ngxDirective contained ssl_password_file
[620] syn keyword ngxDirective contained ssl_prefer_server_ciphers
[621] syn keyword ngxDirective contained ssl_preread
[622] syn keyword ngxDirective contained ssl_protocols
[623] syn keyword ngxDirective contained ssl_reject_handshake
[624] syn keyword ngxDirective contained ssl_session_cache
[625] syn keyword ngxDirective contained ssl_session_ticket_key
[626] syn keyword ngxDirective contained ssl_session_tickets
[627] syn keyword ngxDirective contained ssl_session_timeout
[628] syn keyword ngxDirective contained ssl_stapling
[629] syn keyword ngxDirective contained ssl_stapling_file
[630] syn keyword ngxDirective contained ssl_stapling_responder
[631] syn keyword ngxDirective contained ssl_stapling_verify
[632] syn keyword ngxDirective contained ssl_trusted_certificate
[633] syn keyword ngxDirective contained ssl_verify_client
[634] syn keyword ngxDirective contained ssl_verify_depth
[635] syn keyword ngxDirective contained starttls
[636] syn keyword ngxDirective contained state
[637] syn keyword ngxDirective contained status
[638] syn keyword ngxDirective contained status_format
[639] syn keyword ngxDirective contained status_zone
[640] syn keyword ngxDirective contained sticky
[641] syn keyword ngxDirective contained stub_status
[642] syn keyword ngxDirective contained sub_filter
[643] syn keyword ngxDirective contained sub_filter_last_modified
[644] syn keyword ngxDirective contained sub_filter_once
[645] syn keyword ngxDirective contained sub_filter_types
[646] syn keyword ngxDirective contained subrequest_output_buffer_size
[647] syn keyword ngxDirective contained tcp_nodelay
[648] syn keyword ngxDirective contained tcp_nopush
[649] syn keyword ngxDirective contained thread_pool
[650] syn keyword ngxDirective contained timeout
[651] syn keyword ngxDirective contained timer_resolution
[652] syn keyword ngxDirective contained types_hash_bucket_size
[653] syn keyword ngxDirective contained types_hash_max_size
[654] syn keyword ngxDirective contained underscores_in_headers
[655] syn keyword ngxDirective contained uninitialized_variable_warn
[656] syn keyword ngxDirective contained use
[657] syn keyword ngxDirective contained user
[658] syn keyword ngxDirective contained userid
[659] syn keyword ngxDirective contained userid_domain
[660] syn keyword ngxDirective contained userid_expires
[661] syn keyword ngxDirective contained userid_flags
[662] syn keyword ngxDirective contained userid_mark
[663] syn keyword ngxDirective contained userid_name
[664] syn keyword ngxDirective contained userid_p3p
[665] syn keyword ngxDirective contained userid_path
[666] syn keyword ngxDirective contained userid_service
[667] syn keyword ngxDirective contained uwsgi_bind
[668] syn keyword ngxDirective contained uwsgi_buffer_size
[669] syn keyword ngxDirective contained uwsgi_buffering
[670] syn keyword ngxDirective contained uwsgi_buffers
[671] syn keyword ngxDirective contained uwsgi_busy_buffers_size
[672] syn keyword ngxDirective contained uwsgi_cache
[673] syn keyword ngxDirective contained uwsgi_cache_background_update
[674] syn keyword ngxDirective contained uwsgi_cache_bypass
[675] syn keyword ngxDirective contained uwsgi_cache_key
[676] syn keyword ngxDirective contained uwsgi_cache_lock
[677] syn keyword ngxDirective contained uwsgi_cache_lock_age
[678] syn keyword ngxDirective contained uwsgi_cache_lock_timeout
[679] syn keyword ngxDirective contained uwsgi_cache_max_range_offset
[680] syn keyword ngxDirective contained uwsgi_cache_methods
[681] syn keyword ngxDirective contained uwsgi_cache_min_uses
[682] syn keyword ngxDirective contained uwsgi_cache_path
[683] syn keyword ngxDirective contained uwsgi_cache_purge
[684] syn keyword ngxDirective contained uwsgi_cache_revalidate
[685] syn keyword ngxDirective contained uwsgi_cache_use_stale
[686] syn keyword ngxDirective contained uwsgi_cache_valid
[687] syn keyword ngxDirective contained uwsgi_connect_timeout
[688] syn keyword ngxDirective contained uwsgi_force_ranges
[689] syn keyword ngxDirective contained uwsgi_hide_header
[690] syn keyword ngxDirective contained uwsgi_ignore_client_abort
[691] syn keyword ngxDirective contained uwsgi_ignore_headers
[692] syn keyword ngxDirective contained uwsgi_intercept_errors
[693] syn keyword ngxDirective contained uwsgi_limit_rate
[694] syn keyword ngxDirective contained uwsgi_max_temp_file_size
[695] syn keyword ngxDirective contained uwsgi_modifier1
[696] syn keyword ngxDirective contained uwsgi_modifier2
[697] syn keyword ngxDirective contained uwsgi_next_upstream
[698] syn keyword ngxDirective contained uwsgi_next_upstream_timeout
[699] syn keyword ngxDirective contained uwsgi_next_upstream_tries
[700] syn keyword ngxDirective contained uwsgi_no_cache
[701] syn keyword ngxDirective contained uwsgi_param
[702] syn keyword ngxDirective contained uwsgi_pass_header
[703] syn keyword ngxDirective contained uwsgi_pass_request_body
[704] syn keyword ngxDirective contained uwsgi_pass_request_headers
[705] syn keyword ngxDirective contained uwsgi_read_timeout
[706] syn keyword ngxDirective contained uwsgi_request_buffering
[707] syn keyword ngxDirective contained uwsgi_send_timeout
[708] syn keyword ngxDirective contained uwsgi_socket_keepalive
[709] syn keyword ngxDirective contained uwsgi_ssl_certificate
[710] syn keyword ngxDirective contained uwsgi_ssl_certificate_key
[711] syn keyword ngxDirective contained uwsgi_ssl_ciphers
[712] syn keyword ngxDirective contained uwsgi_ssl_conf_command
[713] syn keyword ngxDirective contained uwsgi_ssl_crl
[714] syn keyword ngxDirective contained uwsgi_ssl_name
[715] syn keyword ngxDirective contained uwsgi_ssl_password_file
[716] syn keyword ngxDirective contained uwsgi_ssl_protocols
[717] syn keyword ngxDirective contained uwsgi_ssl_server_name
[718] syn keyword ngxDirective contained uwsgi_ssl_session_reuse
[719] syn keyword ngxDirective contained uwsgi_ssl_trusted_certificate
[720] syn keyword ngxDirective contained uwsgi_ssl_verify
[721] syn keyword ngxDirective contained uwsgi_ssl_verify_depth
[722] syn keyword ngxDirective contained uwsgi_store
[723] syn keyword ngxDirective contained uwsgi_store_access
[724] syn keyword ngxDirective contained uwsgi_string
[725] syn keyword ngxDirective contained uwsgi_temp_file_write_size
[726] syn keyword ngxDirective contained uwsgi_temp_path
[727] syn keyword ngxDirective contained valid_referers
[728] syn keyword ngxDirective contained variables_hash_bucket_size
[729] syn keyword ngxDirective contained variables_hash_max_size
[730] syn keyword ngxDirective contained worker_aio_requests
[731] syn keyword ngxDirective contained worker_connections
[732] syn keyword ngxDirective contained worker_cpu_affinity
[733] syn keyword ngxDirective contained worker_priority
[734] syn keyword ngxDirective contained worker_processes
[735] syn keyword ngxDirective contained worker_rlimit_core
[736] syn keyword ngxDirective contained worker_rlimit_nofile
[737] syn keyword ngxDirective contained worker_shutdown_timeout
[738] syn keyword ngxDirective contained working_directory
[739] syn keyword ngxDirective contained xclient
[740] syn keyword ngxDirective contained xml_entities
[741] syn keyword ngxDirective contained xslt_last_modified
[742] syn keyword ngxDirective contained xslt_param
[743] syn keyword ngxDirective contained xslt_string_param
[744] syn keyword ngxDirective contained xslt_stylesheet
[745] syn keyword ngxDirective contained xslt_types
[746] syn keyword ngxDirective contained zone
[747] syn keyword ngxDirective contained zone_sync
[748] syn keyword ngxDirective contained zone_sync_buffers
[749] syn keyword ngxDirective contained zone_sync_connect_retry_interval
[750] syn keyword ngxDirective contained zone_sync_connect_timeout
[751] syn keyword ngxDirective contained zone_sync_interval
[752] syn keyword ngxDirective contained zone_sync_recv_buffer_size
[753] syn keyword ngxDirective contained zone_sync_server
[754] syn keyword ngxDirective contained zone_sync_ssl
[755] syn keyword ngxDirective contained zone_sync_ssl_certificate
[756] syn keyword ngxDirective contained zone_sync_ssl_certificate_key
[757] syn keyword ngxDirective contained zone_sync_ssl_ciphers
[758] syn keyword ngxDirective contained zone_sync_ssl_conf_command
[759] syn keyword ngxDirective contained zone_sync_ssl_crl
[760] syn keyword ngxDirective contained zone_sync_ssl_name
[761] syn keyword ngxDirective contained zone_sync_ssl_password_file
[762] syn keyword ngxDirective contained zone_sync_ssl_protocols
[763] syn keyword ngxDirective contained zone_sync_ssl_server_name
[764] syn keyword ngxDirective contained zone_sync_ssl_trusted_certificate
[765] syn keyword ngxDirective contained zone_sync_ssl_verify
[766] syn keyword ngxDirective contained zone_sync_ssl_verify_depth
[767] syn keyword ngxDirective contained zone_sync_timeout
[768] 
[769] 
[770] " 3rd party modules list taken from
[771] " https://github.com/freebsd/freebsd-ports/blob/main/www/nginx-devel/Makefile.extmod
[772] " ----------------------------------------------------------------------------------
[773] 
[774] " https://github.com/msva/nginx_ajp_module
[775] syn keyword ngxDirectiveThirdParty contained ajp_buffer_size
[776] syn keyword ngxDirectiveThirdParty contained ajp_buffers
[777] syn keyword ngxDirectiveThirdParty contained ajp_busy_buffers_size
[778] syn keyword ngxDirectiveThirdParty contained ajp_cache
[779] syn keyword ngxDirectiveThirdParty contained ajp_cache_key
[780] syn keyword ngxDirectiveThirdParty contained ajp_cache_lock
[781] syn keyword ngxDirectiveThirdParty contained ajp_cache_lock_timeout
[782] syn keyword ngxDirectiveThirdParty contained ajp_cache_methods
[783] syn keyword ngxDirectiveThirdParty contained ajp_cache_min_uses
[784] syn keyword ngxDirectiveThirdParty contained ajp_cache_path
[785] syn keyword ngxDirectiveThirdParty contained ajp_cache_use_stale
[786] syn keyword ngxDirectiveThirdParty contained ajp_cache_valid
[787] syn keyword ngxDirectiveThirdParty contained ajp_connect_timeout
[788] syn keyword ngxDirectiveThirdParty contained ajp_header_packet_buffer_size
[789] syn keyword ngxDirectiveThirdParty contained ajp_hide_header
[790] syn keyword ngxDirectiveThirdParty contained ajp_ignore_client_abort
[791] syn keyword ngxDirectiveThirdParty contained ajp_ignore_headers
[792] syn keyword ngxDirectiveThirdParty contained ajp_intercept_errors
[793] syn keyword ngxDirectiveThirdParty contained ajp_keep_conn
[794] syn keyword ngxDirectiveThirdParty contained ajp_max_data_packet_size
[795] syn keyword ngxDirectiveThirdParty contained ajp_max_temp_file_size
[796] syn keyword ngxDirectiveThirdParty contained ajp_next_upstream
[797] syn keyword ngxDirectiveThirdParty contained ajp_param
[798] syn keyword ngxDirectiveThirdParty contained ajp_pass
[799] syn keyword ngxDirectiveThirdParty contained ajp_pass_header
[800] syn keyword ngxDirectiveThirdParty contained ajp_pass_request_body
[801] syn keyword ngxDirectiveThirdParty contained ajp_pass_request_headers
[802] syn keyword ngxDirectiveThirdParty contained ajp_read_timeout
[803] syn keyword ngxDirectiveThirdParty contained ajp_script_url
[804] syn keyword ngxDirectiveThirdParty contained ajp_secret
[805] syn keyword ngxDirectiveThirdParty contained ajp_send_lowat
[806] syn keyword ngxDirectiveThirdParty contained ajp_send_timeout
[807] syn keyword ngxDirectiveThirdParty contained ajp_store
[808] syn keyword ngxDirectiveThirdParty contained ajp_store_access
[809] syn keyword ngxDirectiveThirdParty contained ajp_temp_file_write_size
[810] syn keyword ngxDirectiveThirdParty contained ajp_temp_path
[811] syn keyword ngxDirectiveThirdParty contained ajp_upstream_fail_timeout
[812] syn keyword ngxDirectiveThirdParty contained ajp_upstream_max_fails
[813] 
[814] " https://github.com/openresty/array-var-nginx-module
[815] syn keyword ngxDirectiveThirdParty contained array_join
[816] syn keyword ngxDirectiveThirdParty contained array_map
[817] syn keyword ngxDirectiveThirdParty contained array_map_op
[818] syn keyword ngxDirectiveThirdParty contained array_split
[819] 
[820] " https://github.com/anomalizer/ngx_aws_auth
[821] syn keyword ngxDirectiveThirdParty contained aws_access_key
[822] syn keyword ngxDirectiveThirdParty contained aws_endpoint
[823] syn keyword ngxDirectiveThirdParty contained aws_key_scope
[824] syn keyword ngxDirectiveThirdParty contained aws_s3_bucket
[825] syn keyword ngxDirectiveThirdParty contained aws_sign
[826] syn keyword ngxDirectiveThirdParty contained aws_signing_key
[827] 
[828] " https://github.com/google/ngx_brotli
[829] syn keyword ngxDirectiveThirdParty contained brotli
[830] syn keyword ngxDirectiveThirdParty contained brotli_buffers
[831] syn keyword ngxDirectiveThirdParty contained brotli_comp_level
[832] syn keyword ngxDirectiveThirdParty contained brotli_min_length
[833] syn keyword ngxDirectiveThirdParty contained brotli_static
[834] syn keyword ngxDirectiveThirdParty contained brotli_types
[835] syn keyword ngxDirectiveThirdParty contained brotli_window
[836] 
[837] " https://github.com/torden/ngx_cache_purge
[838] syn keyword ngxDirectiveThirdParty contained cache_purge_response_type
[839] 
[840] " https://github.com/nginx-clojure/nginx-clojure
[841] syn keyword ngxDirectiveThirdParty contained access_handler_code
[842] syn keyword ngxDirectiveThirdParty contained access_handler_name
[843] syn keyword ngxDirectiveThirdParty contained access_handler_property
[844] syn keyword ngxDirectiveThirdParty contained access_handler_type
[845] syn keyword ngxDirectiveThirdParty contained always_read_body
[846] syn keyword ngxDirectiveThirdParty contained auto_upgrade_ws
[847] syn keyword ngxDirectiveThirdParty contained body_filter_code
[848] syn keyword ngxDirectiveThirdParty contained body_filter_name
[849] syn keyword ngxDirectiveThirdParty contained body_filter_property
[850] syn keyword ngxDirectiveThirdParty contained body_filter_type
[851] syn keyword ngxDirectiveThirdParty contained content_handler_code
[852] syn keyword ngxDirectiveThirdParty contained content_handler_name
[853] syn keyword ngxDirectiveThirdParty contained content_handler_property
[854] syn keyword ngxDirectiveThirdParty contained content_handler_type
[855] syn keyword ngxDirectiveThirdParty contained handler_code
[856] syn keyword ngxDirectiveThirdParty contained handler_name
[857] syn keyword ngxDirectiveThirdParty contained handler_type
[858] syn keyword ngxDirectiveThirdParty contained handlers_lazy_init
[859] syn keyword ngxDirectiveThirdParty contained header_filter_code
[860] syn keyword ngxDirectiveThirdParty contained header_filter_name
[861] syn keyword ngxDirectiveThirdParty contained header_filter_property
[862] syn keyword ngxDirectiveThirdParty contained header_filter_type
[863] syn keyword ngxDirectiveThirdParty contained jvm_classpath
[864] syn keyword ngxDirectiveThirdParty contained jvm_classpath_check
[865] syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_code
[866] syn keyword ngxDirectiveThirdParty contained jvm_exit_handler_name
[867] syn keyword ngxDirectiveThirdParty contained jvm_handler_type
[868] syn keyword ngxDirectiveThirdParty contained jvm_init_handler_code
[869] syn keyword ngxDirectiveThirdParty contained jvm_init_handler_name
[870] syn keyword ngxDirectiveThirdParty contained jvm_options
[871] syn keyword ngxDirectiveThirdParty contained jvm_path
[872] syn keyword ngxDirectiveThirdParty contained jvm_var
[873] syn keyword ngxDirectiveThirdParty contained jvm_workers
[874] syn keyword ngxDirectiveThirdParty contained log_handler_code
[875] syn keyword ngxDirectiveThirdParty contained log_handler_name
[876] syn keyword ngxDirectiveThirdParty contained log_handler_property
[877] syn keyword ngxDirectiveThirdParty contained log_handler_type
[878] syn keyword ngxDirectiveThirdParty contained max_balanced_tcp_connections
[879] syn keyword ngxDirectiveThirdParty contained rewrite_handler_code
[880] syn keyword ngxDirectiveThirdParty contained rewrite_handler_name
[881] syn keyword ngxDirectiveThirdParty contained rewrite_handler_property
[882] syn keyword ngxDirectiveThirdParty contained rewrite_handler_type
[883] syn keyword ngxDirectiveThirdParty contained shared_map
[884] syn keyword ngxDirectiveThirdParty contained write_page_size
[885] 
[886] " https://github.com/AirisX/nginx_cookie_flag_module
[887] syn keyword ngxDirectiveThirdParty contained set_cookie_flag
[888] 
[889] " https://github.com/grahamedgecombe/nginx-ct
[890] syn keyword ngxDirectiveThirdParty contained ssl_ct
[891] syn keyword ngxDirectiveThirdParty contained ssl_ct_static_scts
[892] 
[893] " https://github.com/openresty/echo-nginx-module
[894] syn keyword ngxDirectiveThirdParty contained echo
[895] syn keyword ngxDirectiveThirdParty contained echo_abort_parent
[896] syn keyword ngxDirectiveThirdParty contained echo_after_body
[897] syn keyword ngxDirectiveThirdParty contained echo_before_body
[898] syn keyword ngxDirectiveThirdParty contained echo_blocking_sleep
[899] syn keyword ngxDirectiveThirdParty contained echo_duplicate
[900] syn keyword ngxDirectiveThirdParty contained echo_end
[901] syn keyword ngxDirectiveThirdParty contained echo_exec
[902] syn keyword ngxDirectiveThirdParty contained echo_flush
[903] syn keyword ngxDirectiveThirdParty contained echo_foreach_split
[904] syn keyword ngxDirectiveThirdParty contained echo_location
[905] syn keyword ngxDirectiveThirdParty contained echo_location_async
[906] syn keyword ngxDirectiveThirdParty contained echo_read_request_body
[907] syn keyword ngxDirectiveThirdParty contained echo_request_body
[908] syn keyword ngxDirectiveThirdParty contained echo_reset_timer
[909] syn keyword ngxDirectiveThirdParty contained echo_sleep
[910] syn keyword ngxDirectiveThirdParty contained echo_status
[911] syn keyword ngxDirectiveThirdParty contained echo_subrequest
[912] syn keyword ngxDirectiveThirdParty contained echo_subrequest_async
[913] 
[914] " https://github.com/openresty/drizzle-nginx-module
[915] syn keyword ngxDirectiveThirdParty contained drizzle_buffer_size
[916] syn keyword ngxDirectiveThirdParty contained drizzle_connect_timeout
[917] syn keyword ngxDirectiveThirdParty contained drizzle_dbname
[918] syn keyword ngxDirectiveThirdParty contained drizzle_keepalive
[919] syn keyword ngxDirectiveThirdParty contained drizzle_module_header
[920] syn keyword ngxDirectiveThirdParty contained drizzle_pass
[921] syn keyword ngxDirectiveThirdParty contained drizzle_query
[922] syn keyword ngxDirectiveThirdParty contained drizzle_recv_cols_timeout
[923] syn keyword ngxDirectiveThirdParty contained drizzle_recv_rows_timeout
[924] syn keyword ngxDirectiveThirdParty contained drizzle_send_query_timeout
[925] syn keyword ngxDirectiveThirdParty contained drizzle_server
[926] syn keyword ngxDirectiveThirdParty contained drizzle_status
[927] 
[928] " https://github.com/ZigzagAK/ngx_dynamic_upstream
[929] syn keyword ngxDirectiveThirdParty contained dns_add_down
[930] syn keyword ngxDirectiveThirdParty contained dns_ipv6
[931] syn keyword ngxDirectiveThirdParty contained dns_update
[932] syn keyword ngxDirectiveThirdParty contained dynamic_state_file
[933] syn keyword ngxDirectiveThirdParty contained dynamic_upstream
[934] 
[935] " https://github.com/ZigzagAK/ngx_dynamic_healthcheck
[936] syn keyword ngxDirectiveThirdParty contained check
[937] syn keyword ngxDirectiveThirdParty contained check_disable_host
[938] syn keyword ngxDirectiveThirdParty contained check_exclude_host
[939] syn keyword ngxDirectiveThirdParty contained check_persistent
[940] syn keyword ngxDirectiveThirdParty contained check_request_body
[941] syn keyword ngxDirectiveThirdParty contained check_request_headers
[942] syn keyword ngxDirectiveThirdParty contained check_request_uri
[943] syn keyword ngxDirectiveThirdParty contained check_response_body
[944] syn keyword ngxDirectiveThirdParty contained check_response_codes
[945] syn keyword ngxDirectiveThirdParty contained healthcheck
[946] syn keyword ngxDirectiveThirdParty contained healthcheck_buffer_size
[947] syn keyword ngxDirectiveThirdParty contained healthcheck_disable_host
[948] syn keyword ngxDirectiveThirdParty contained healthcheck_get
[949] syn keyword ngxDirectiveThirdParty contained healthcheck_persistent
[950] syn keyword ngxDirectiveThirdParty contained healthcheck_request_body
[951] syn keyword ngxDirectiveThirdParty contained healthcheck_request_headers
[952] syn keyword ngxDirectiveThirdParty contained healthcheck_request_uri
[953] syn keyword ngxDirectiveThirdParty contained healthcheck_response_body
[954] syn keyword ngxDirectiveThirdParty contained healthcheck_response_codes
[955] syn keyword ngxDirectiveThirdParty contained healthcheck_status
[956] syn keyword ngxDirectiveThirdParty contained healthcheck_update
[957] 
[958] " https://github.com/openresty/encrypted-session-nginx-module
[959] syn keyword ngxDirectiveThirdParty contained encrypted_session_expires
[960] syn keyword ngxDirectiveThirdParty contained encrypted_session_iv
[961] syn keyword ngxDirectiveThirdParty contained encrypted_session_key
[962] syn keyword ngxDirectiveThirdParty contained set_decrypt_session
[963] syn keyword ngxDirectiveThirdParty contained set_encrypt_session
[964] 
[965] " https://github.com/calio/form-input-nginx-module
[966] syn keyword ngxDirectiveThirdParty contained set_form_input
[967] syn keyword ngxDirectiveThirdParty contained set_form_input_multi
[968] 
[969] " https://github.com/nieoding/nginx-gridfs
[970] syn keyword ngxDirectiveThirdParty contained gridfs
[971] syn keyword ngxDirectiveThirdParty contained mongo
[972] 
[973] " https://github.com/openresty/headers-more-nginx-module
[974] syn keyword ngxDirectiveThirdParty contained more_clear_headers
[975] syn keyword ngxDirectiveThirdParty contained more_clear_input_headers
[976] syn keyword ngxDirectiveThirdParty contained more_set_headers
[977] syn keyword ngxDirectiveThirdParty contained more_set_input_headers
[978] 
[979] " https://github.com/dvershinin/nginx_accept_language_module
[980] syn keyword ngxDirectiveThirdParty contained set_from_accept_language
[981] 
[982] " https://github.com/atomx/nginx-http-auth-digest
[983] syn keyword ngxDirectiveThirdParty contained auth_digest
[984] syn keyword ngxDirectiveThirdParty contained auth_digest_drop_time
[985] syn keyword ngxDirectiveThirdParty contained auth_digest_evasion_time
[986] syn keyword ngxDirectiveThirdParty contained auth_digest_expires
[987] syn keyword ngxDirectiveThirdParty contained auth_digest_maxtries
[988] syn keyword ngxDirectiveThirdParty contained auth_digest_replays
[989] syn keyword ngxDirectiveThirdParty contained auth_digest_shm_size
[990] syn keyword ngxDirectiveThirdParty contained auth_digest_timeout
[991] syn keyword ngxDirectiveThirdParty contained auth_digest_user_file
[992] 
[993] " https://github.com/stnoonan/spnego-http-auth-nginx-module
[994] syn keyword ngxDirectiveThirdParty contained auth_gss
[995] syn keyword ngxDirectiveThirdParty contained auth_gss_allow_basic_fallback
[996] syn keyword ngxDirectiveThirdParty contained auth_gss_authorized_principal
[997] syn keyword ngxDirectiveThirdParty contained auth_gss_authorized_principal_regex
[998] syn keyword ngxDirectiveThirdParty contained auth_gss_constrained_delegation
[999] syn keyword ngxDirectiveThirdParty contained auth_gss_delegate_credentials
[1000] syn keyword ngxDirectiveThirdParty contained auth_gss_force_realm
[1001] syn keyword ngxDirectiveThirdParty contained auth_gss_format_full
[1002] syn keyword ngxDirectiveThirdParty contained auth_gss_keytab
[1003] syn keyword ngxDirectiveThirdParty contained auth_gss_map_to_local
[1004] syn keyword ngxDirectiveThirdParty contained auth_gss_realm
[1005] syn keyword ngxDirectiveThirdParty contained auth_gss_service_ccache
[1006] syn keyword ngxDirectiveThirdParty contained auth_gss_service_name
[1007] 
[1008] " https://github.com/kvspb/nginx-auth-ldap
[1009] syn keyword ngxDirectiveThirdParty contained auth_ldap
[1010] syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_enabled
[1011] syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_expiration_time
[1012] syn keyword ngxDirectiveThirdParty contained auth_ldap_cache_size
[1013] syn keyword ngxDirectiveThirdParty contained auth_ldap_servers
[1014] syn keyword ngxDirectiveThirdParty contained auth_ldap_servers_size
[1015] syn keyword ngxDirectiveThirdParty contained ldap_server
[1016] 
[1017] " https://github.com/sto/ngx_http_auth_pam_module
[1018] syn keyword ngxDirectiveThirdParty contained auth_pam
[1019] syn keyword ngxDirectiveThirdParty contained auth_pam_service_name
[1020] syn keyword ngxDirectiveThirdParty contained auth_pam_set_pam_env
[1021] 
[1022] " https://github.com/arut/nginx-dav-ext-module
[1023] syn keyword ngxDirectiveThirdParty contained dav_ext_lock
[1024] syn keyword ngxDirectiveThirdParty contained dav_ext_lock_zone
[1025] syn keyword ngxDirectiveThirdParty contained dav_ext_methods
[1026] 
[1027] " https://github.com/openresty/nginx-eval-module
[1028] syn keyword ngxDirectiveThirdParty contained eval
[1029] syn keyword ngxDirectiveThirdParty contained eval_buffer_size
[1030] syn keyword ngxDirectiveThirdParty contained eval_escalate
[1031] syn keyword ngxDirectiveThirdParty contained eval_override_content_type
[1032] syn keyword ngxDirectiveThirdParty contained eval_subrequest_in_memory
[1033] 
[1034] " https://github.com/aperezdc/ngx-fancyindex
[1035] syn keyword ngxDirectiveThirdParty contained fancyindex
[1036] syn keyword ngxDirectiveThirdParty contained fancyindex_css_href
[1037] syn keyword ngxDirectiveThirdParty contained fancyindex_default_sort
[1038] syn keyword ngxDirectiveThirdParty contained fancyindex_directories_first
[1039] syn keyword ngxDirectiveThirdParty contained fancyindex_exact_size
[1040] syn keyword ngxDirectiveThirdParty contained fancyindex_footer
[1041] syn keyword ngxDirectiveThirdParty contained fancyindex_header
[1042] syn keyword ngxDirectiveThirdParty contained fancyindex_hide_parent_dir
[1043] syn keyword ngxDirectiveThirdParty contained fancyindex_hide_symlinks
[1044] syn keyword ngxDirectiveThirdParty contained fancyindex_ignore
[1045] syn keyword ngxDirectiveThirdParty contained fancyindex_localtime
[1046] syn keyword ngxDirectiveThirdParty contained fancyindex_show_dotfiles
[1047] syn keyword ngxDirectiveThirdParty contained fancyindex_show_path
[1048] syn keyword ngxDirectiveThirdParty contained fancyindex_time_format
[1049] 
[1050] " https://github.com/alibaba/nginx-http-footer-filter
[1051] syn keyword ngxDirectiveThirdParty contained footer
[1052] syn keyword ngxDirectiveThirdParty contained footer_types
[1053] 
[1054] " https://github.com/leev/ngx_http_geoip2_module
[1055] syn keyword ngxDirectiveThirdParty contained geoip2
[1056] syn keyword ngxDirectiveThirdParty contained geoip2_proxy
[1057] syn keyword ngxDirectiveThirdParty contained geoip2_proxy_recursive
[1058] 
[1059] " https://github.com/ip2location/ip2location-nginx
[1060] syn keyword ngxDirectiveThirdParty contained ip2location_database
[1061] syn keyword ngxDirectiveThirdParty contained ip2location_proxy
[1062] syn keyword ngxDirectiveThirdParty contained ip2location_proxy_recursive
[1063] 
[1064] " https://github.com/ip2location/ip2proxy-nginx
[1065] syn keyword ngxDirectiveThirdParty contained ip2proxy_database
[1066] syn keyword ngxDirectiveThirdParty contained ip2proxy_proxy
[1067] syn keyword ngxDirectiveThirdParty contained ip2proxy_proxy_recursive
[1068] 
[1069] " https://github.com/kr/nginx-notice
[1070] syn keyword ngxDirectiveThirdParty contained notice
[1071] syn keyword ngxDirectiveThirdParty contained notice_type
[1072] 
[1073] " https://github.com/slact/nchan
[1074] syn keyword ngxDirectiveThirdParty contained nchan_access_control_allow_credentials
[1075] syn keyword ngxDirectiveThirdParty contained nchan_access_control_allow_origin
[1076] syn keyword ngxDirectiveThirdParty contained nchan_authorize_request
[1077] syn keyword ngxDirectiveThirdParty contained nchan_benchmark
[1078] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_channels
[1079] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_message_padding_bytes
[1080] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_messages_per_channel_per_minute
[1081] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_publisher_distribution
[1082] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_subscriber_distribution
[1083] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_subscribers_per_channel
[1084] syn keyword ngxDirectiveThirdParty contained nchan_benchmark_time
[1085] syn keyword ngxDirectiveThirdParty contained nchan_channel_event_string
[1086] syn keyword ngxDirectiveThirdParty contained nchan_channel_events_channel_id
[1087] syn keyword ngxDirectiveThirdParty contained nchan_channel_group
[1088] syn keyword ngxDirectiveThirdParty contained nchan_channel_group_accounting
[1089] syn keyword ngxDirectiveThirdParty contained nchan_channel_id
[1090] syn keyword ngxDirectiveThirdParty contained nchan_channel_id_split_delimiter
[1091] syn keyword ngxDirectiveThirdParty contained nchan_channel_timeout
[1092] syn keyword ngxDirectiveThirdParty contained nchan_deflate_message_for_websocket
[1093] syn keyword ngxDirectiveThirdParty contained nchan_eventsource_event
[1094] syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_comment
[1095] syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_data
[1096] syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_event
[1097] syn keyword ngxDirectiveThirdParty contained nchan_eventsource_ping_interval
[1098] syn keyword ngxDirectiveThirdParty contained nchan_group_location
[1099] syn keyword ngxDirectiveThirdParty contained nchan_group_max_channels
[1100] syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages
[1101] syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_disk
[1102] syn keyword ngxDirectiveThirdParty contained nchan_group_max_messages_memory
[1103] syn keyword ngxDirectiveThirdParty contained nchan_group_max_subscribers
[1104] syn keyword ngxDirectiveThirdParty contained nchan_longpoll_multipart_response
[1105] syn keyword ngxDirectiveThirdParty contained nchan_max_channel_id_length
[1106] syn keyword ngxDirectiveThirdParty contained nchan_max_channel_subscribers
[1107] syn keyword ngxDirectiveThirdParty contained nchan_max_reserved_memory
[1108] syn keyword ngxDirectiveThirdParty contained nchan_message_buffer_length
[1109] syn keyword ngxDirectiveThirdParty contained nchan_message_max_buffer_length
[1110] syn keyword ngxDirectiveThirdParty contained nchan_message_temp_path
[1111] syn keyword ngxDirectiveThirdParty contained nchan_message_timeout
[1112] syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_level
[1113] syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_memlevel
[1114] syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_strategy
[1115] syn keyword ngxDirectiveThirdParty contained nchan_permessage_deflate_compression_window
[1116] syn keyword ngxDirectiveThirdParty contained nchan_pub_channel_id
[1117] syn keyword ngxDirectiveThirdParty contained nchan_publisher
[1118] syn keyword ngxDirectiveThirdParty contained nchan_publisher_channel_id
[1119] syn keyword ngxDirectiveThirdParty contained nchan_publisher_location
[1120] syn keyword ngxDirectiveThirdParty contained nchan_publisher_upstream_request
[1121] syn keyword ngxDirectiveThirdParty contained nchan_pubsub
[1122] syn keyword ngxDirectiveThirdParty contained nchan_pubsub_channel_id
[1123] syn keyword ngxDirectiveThirdParty contained nchan_pubsub_location
[1124] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval
[1125] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_backoff
[1126] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_jitter
[1127] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_max
[1128] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_check_interval_min
[1129] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_connect_timeout
[1130] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_max_failing_time
[1131] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay
[1132] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_backoff
[1133] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_jitter
[1134] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_max
[1135] syn keyword ngxDirectiveThirdParty contained nchan_redis_cluster_recovery_delay_min
[1136] syn keyword ngxDirectiveThirdParty contained nchan_redis_command_timeout
[1137] syn keyword ngxDirectiveThirdParty contained nchan_redis_connect_timeout
[1138] syn keyword ngxDirectiveThirdParty contained nchan_redis_discovered_ip_range_blacklist
[1139] syn keyword ngxDirectiveThirdParty contained nchan_redis_fakesub_timer_interval
[1140] syn keyword ngxDirectiveThirdParty contained nchan_redis_idle_channel_cache_timeout
[1141] syn keyword ngxDirectiveThirdParty contained nchan_redis_load_scripts_unconditionally
[1142] syn keyword ngxDirectiveThirdParty contained nchan_redis_namespace
[1143] syn keyword ngxDirectiveThirdParty contained nchan_redis_node_connect_timeout
[1144] syn keyword ngxDirectiveThirdParty contained nchan_redis_nostore_fastpublish
[1145] syn keyword ngxDirectiveThirdParty contained nchan_redis_optimize_target
[1146] syn keyword ngxDirectiveThirdParty contained nchan_redis_pass
[1147] syn keyword ngxDirectiveThirdParty contained nchan_redis_pass_inheritable
[1148] syn keyword ngxDirectiveThirdParty contained nchan_redis_password
[1149] syn keyword ngxDirectiveThirdParty contained nchan_redis_ping_interval
[1150] syn keyword ngxDirectiveThirdParty contained nchan_redis_publish_msgpacked_max_size
[1151] syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay
[1152] syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_backoff
[1153] syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_jitter
[1154] syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_max
[1155] syn keyword ngxDirectiveThirdParty contained nchan_redis_reconnect_delay_min
[1156] syn keyword ngxDirectiveThirdParty contained nchan_redis_retry_commands
[1157] syn keyword ngxDirectiveThirdParty contained nchan_redis_retry_commands_max_wait
[1158] syn keyword ngxDirectiveThirdParty contained nchan_redis_server
[1159] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl
[1160] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_ciphers
[1161] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_client_certificate
[1162] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_client_certificate_key
[1163] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_server_name
[1164] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_trusted_certificate
[1165] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_trusted_certificate_path
[1166] syn keyword ngxDirectiveThirdParty contained nchan_redis_ssl_verify_certificate
[1167] syn keyword ngxDirectiveThirdParty contained nchan_redis_storage_mode
[1168] syn keyword ngxDirectiveThirdParty contained nchan_redis_subscribe_weights
[1169] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls
[1170] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_ciphers
[1171] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_client_certificate
[1172] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_server_name
[1173] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_trusted_certificate
[1174] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_trusted_certificate_path
[1175] syn keyword ngxDirectiveThirdParty contained nchan_redis_tls_verify_certificate
[1176] syn keyword ngxDirectiveThirdParty contained nchan_redis_url
[1177] syn keyword ngxDirectiveThirdParty contained nchan_redis_username
[1178] syn keyword ngxDirectiveThirdParty contained nchan_redis_wait_after_connecting
[1179] syn keyword ngxDirectiveThirdParty contained nchan_shared_memory_size
[1180] syn keyword ngxDirectiveThirdParty contained nchan_storage_engine
[1181] syn keyword ngxDirectiveThirdParty contained nchan_store_messages
[1182] syn keyword ngxDirectiveThirdParty contained nchan_stub_status
[1183] syn keyword ngxDirectiveThirdParty contained nchan_sub_channel_id
[1184] syn keyword ngxDirectiveThirdParty contained nchan_subscribe_existing_channels_only
[1185] syn keyword ngxDirectiveThirdParty contained nchan_subscribe_request
[1186] syn keyword ngxDirectiveThirdParty contained nchan_subscriber
[1187] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_channel_id
[1188] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_compound_etag_message_id
[1189] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_first_message
[1190] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_http_raw_stream_separator
[1191] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_info
[1192] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_info_string
[1193] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_last_message_id
[1194] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_location
[1195] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_message_id_custom_etag_header
[1196] syn keyword ngxDirectiveThirdParty contained nchan_subscriber_timeout
[1197] syn keyword ngxDirectiveThirdParty contained nchan_unsubscribe_request
[1198] syn keyword ngxDirectiveThirdParty contained nchan_use_redis
[1199] syn keyword ngxDirectiveThirdParty contained nchan_websocket_client_heartbeat
[1200] syn keyword ngxDirectiveThirdParty contained nchan_websocket_ping_interval
[1201] syn keyword ngxDirectiveThirdParty contained push_authorized_channels_only
[1202] syn keyword ngxDirectiveThirdParty contained push_channel_group
[1203] syn keyword ngxDirectiveThirdParty contained push_channel_timeout
[1204] syn keyword ngxDirectiveThirdParty contained push_max_channel_id_length
[1205] syn keyword ngxDirectiveThirdParty contained push_max_channel_subscribers
[1206] syn keyword ngxDirectiveThirdParty contained push_max_message_buffer_length
[1207] syn keyword ngxDirectiveThirdParty contained push_max_reserved_memory
[1208] syn keyword ngxDirectiveThirdParty contained push_message_buffer_length
[1209] syn keyword ngxDirectiveThirdParty contained push_message_timeout
[1210] syn keyword ngxDirectiveThirdParty contained push_min_message_buffer_length
[1211] syn keyword ngxDirectiveThirdParty contained push_publisher
[1212] syn keyword ngxDirectiveThirdParty contained push_store_messages
[1213] syn keyword ngxDirectiveThirdParty contained push_subscriber
[1214] syn keyword ngxDirectiveThirdParty contained push_subscriber_concurrency
[1215] syn keyword ngxDirectiveThirdParty contained push_subscriber_timeout
[1216] 
[1217] " https://github.com/wandenberg/nginx-push-stream-module
[1218] syn keyword ngxDirectiveThirdParty contained push_stream_allow_connections_to_events_channel
[1219] syn keyword ngxDirectiveThirdParty contained push_stream_allowed_origins
[1220] syn keyword ngxDirectiveThirdParty contained push_stream_authorized_channels_only
[1221] syn keyword ngxDirectiveThirdParty contained push_stream_channel_deleted_message_text
[1222] syn keyword ngxDirectiveThirdParty contained push_stream_channel_inactivity_time
[1223] syn keyword ngxDirectiveThirdParty contained push_stream_channel_info_on_publish
[1224] syn keyword ngxDirectiveThirdParty contained push_stream_channels_path
[1225] syn keyword ngxDirectiveThirdParty contained push_stream_channels_statistics
[1226] syn keyword ngxDirectiveThirdParty contained push_stream_events_channel_id
[1227] syn keyword ngxDirectiveThirdParty contained push_stream_footer_template
[1228] syn keyword ngxDirectiveThirdParty contained push_stream_header_template
[1229] syn keyword ngxDirectiveThirdParty contained push_stream_header_template_file
[1230] syn keyword ngxDirectiveThirdParty contained push_stream_last_event_id
[1231] syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_tag
[1232] syn keyword ngxDirectiveThirdParty contained push_stream_last_received_message_time
[1233] syn keyword ngxDirectiveThirdParty contained push_stream_longpolling_connection_ttl
[1234] syn keyword ngxDirectiveThirdParty contained push_stream_max_channel_id_length
[1235] syn keyword ngxDirectiveThirdParty contained push_stream_max_messages_stored_per_channel
[1236] syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_channels
[1237] syn keyword ngxDirectiveThirdParty contained push_stream_max_number_of_wildcard_channels
[1238] syn keyword ngxDirectiveThirdParty contained push_stream_max_subscribers_per_channel
[1239] syn keyword ngxDirectiveThirdParty contained push_stream_message_template
[1240] syn keyword ngxDirectiveThirdParty contained push_stream_message_ttl
[1241] syn keyword ngxDirectiveThirdParty contained push_stream_padding_by_user_agent
[1242] syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_interval
[1243] syn keyword ngxDirectiveThirdParty contained push_stream_ping_message_text
[1244] syn keyword ngxDirectiveThirdParty contained push_stream_publisher
[1245] syn keyword ngxDirectiveThirdParty contained push_stream_shared_memory_size
[1246] syn keyword ngxDirectiveThirdParty contained push_stream_store_messages
[1247] syn keyword ngxDirectiveThirdParty contained push_stream_subscriber
[1248] syn keyword ngxDirectiveThirdParty contained push_stream_subscriber_connection_ttl
[1249] syn keyword ngxDirectiveThirdParty contained push_stream_timeout_with_body
[1250] syn keyword ngxDirectiveThirdParty contained push_stream_user_agent
[1251] syn keyword ngxDirectiveThirdParty contained push_stream_websocket_allow_publish
[1252] syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_max_qtd
[1253] syn keyword ngxDirectiveThirdParty contained push_stream_wildcard_channel_prefix
[1254] 
[1255] " https://github.com/yaoweibin/ngx_http_substitutions_filter_module
[1256] syn keyword ngxDirectiveThirdParty contained subs_buffers
[1257] syn keyword ngxDirectiveThirdParty contained subs_filter
[1258] syn keyword ngxDirectiveThirdParty contained subs_filter_bypass
[1259] syn keyword ngxDirectiveThirdParty contained subs_filter_types
[1260] syn keyword ngxDirectiveThirdParty contained subs_line_buffer_size
[1261] 
[1262] " https://github.com/tarantool/nginx_upstream_module
[1263] syn keyword ngxDirectiveThirdParty contained tnt_allowed_indexes
[1264] syn keyword ngxDirectiveThirdParty contained tnt_allowed_spaces
[1265] syn keyword ngxDirectiveThirdParty contained tnt_buffer_size
[1266] syn keyword ngxDirectiveThirdParty contained tnt_connect_timeout
[1267] syn keyword ngxDirectiveThirdParty contained tnt_delete
[1268] syn keyword ngxDirectiveThirdParty contained tnt_http_methods
[1269] syn keyword ngxDirectiveThirdParty contained tnt_http_rest_methods
[1270] syn keyword ngxDirectiveThirdParty contained tnt_in_multiplier
[1271] syn keyword ngxDirectiveThirdParty contained tnt_insert
[1272] syn keyword ngxDirectiveThirdParty contained tnt_method
[1273] syn keyword ngxDirectiveThirdParty contained tnt_multireturn_skip_count
[1274] syn keyword ngxDirectiveThirdParty contained tnt_next_upstream
[1275] syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_timeout
[1276] syn keyword ngxDirectiveThirdParty contained tnt_next_upstream_tries
[1277] syn keyword ngxDirectiveThirdParty contained tnt_out_multiplier
[1278] syn keyword ngxDirectiveThirdParty contained tnt_pass
[1279] syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request
[1280] syn keyword ngxDirectiveThirdParty contained tnt_pass_http_request_buffer_size
[1281] syn keyword ngxDirectiveThirdParty contained tnt_pure_result
[1282] syn keyword ngxDirectiveThirdParty contained tnt_read_timeout
[1283] syn keyword ngxDirectiveThirdParty contained tnt_replace
[1284] syn keyword ngxDirectiveThirdParty contained tnt_select
[1285] syn keyword ngxDirectiveThirdParty contained tnt_select_limit_max
[1286] syn keyword ngxDirectiveThirdParty contained tnt_send_timeout
[1287] syn keyword ngxDirectiveThirdParty contained tnt_set_header
[1288] syn keyword ngxDirectiveThirdParty contained tnt_update
[1289] syn keyword ngxDirectiveThirdParty contained tnt_upsert
[1290] 
[1291] " https://github.com/fdintino/nginx-upload-module
[1292] syn keyword ngxDirectiveThirdParty contained upload_add_header
[1293] syn keyword ngxDirectiveThirdParty contained upload_aggregate_form_field
[1294] syn keyword ngxDirectiveThirdParty contained upload_buffer_size
[1295] syn keyword ngxDirectiveThirdParty contained upload_cleanup
[1296] syn keyword ngxDirectiveThirdParty contained upload_empty_fiels_names
[1297] syn keyword ngxDirectiveThirdParty contained upload_limit_rate
[1298] syn keyword ngxDirectiveThirdParty contained upload_max_file_size
[1299] syn keyword ngxDirectiveThirdParty contained upload_max_output_body_len
[1300] syn keyword ngxDirectiveThirdParty contained upload_max_part_header_len
[1301] syn keyword ngxDirectiveThirdParty contained upload_merge_buffer_size
[1302] syn keyword ngxDirectiveThirdParty contained upload_pass
[1303] syn keyword ngxDirectiveThirdParty contained upload_pass_args
[1304] syn keyword ngxDirectiveThirdParty contained upload_pass_form_field
[1305] syn keyword ngxDirectiveThirdParty contained upload_range_header_buffer_size
[1306] syn keyword ngxDirectiveThirdParty contained upload_resumable
[1307] syn keyword ngxDirectiveThirdParty contained upload_set_form_field
[1308] syn keyword ngxDirectiveThirdParty contained upload_state_store
[1309] syn keyword ngxDirectiveThirdParty contained upload_store
[1310] syn keyword ngxDirectiveThirdParty contained upload_store_access
[1311] syn keyword ngxDirectiveThirdParty contained upload_tame_arrays
[1312] 
[1313] " https://github.com/masterzen/nginx-upload-progress-module
[1314] syn keyword ngxDirectiveThirdParty contained report_uploads
[1315] syn keyword ngxDirectiveThirdParty contained track_uploads
[1316] syn keyword ngxDirectiveThirdParty contained upload_progress
[1317] syn keyword ngxDirectiveThirdParty contained upload_progress_content_type
[1318] syn keyword ngxDirectiveThirdParty contained upload_progress_header
[1319] syn keyword ngxDirectiveThirdParty contained upload_progress_java_output
[1320] syn keyword ngxDirectiveThirdParty contained upload_progress_json_output
[1321] syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_output
[1322] syn keyword ngxDirectiveThirdParty contained upload_progress_jsonp_parameter
[1323] syn keyword ngxDirectiveThirdParty contained upload_progress_template
[1324] 
[1325] " https://github.com/yaoweibin/nginx_upstream_check_module
[1326] syn keyword ngxDirectiveThirdParty contained check_fastcgi_param
[1327] syn keyword ngxDirectiveThirdParty contained check_http_expect_alive
[1328] syn keyword ngxDirectiveThirdParty contained check_http_send
[1329] syn keyword ngxDirectiveThirdParty contained check_keepalive_requests
[1330] syn keyword ngxDirectiveThirdParty contained check_shm_size
[1331] syn keyword ngxDirectiveThirdParty contained check_status
[1332] 
[1333] " https://github.com/jaygooby/nginx-upstream-fair
[1334] syn keyword ngxDirectiveThirdParty contained fair
[1335] syn keyword ngxDirectiveThirdParty contained upstream_fair_shm_size
[1336] 
[1337] " https://github.com/ayty-adrianomartins/nginx-sticky-module-ng
[1338] syn keyword ngxDirectiveThirdParty contained sticky_no_fallback
[1339] 
[1340] " https://github.com/Novetta/nginx-video-thumbextractor-module
[1341] syn keyword ngxDirectiveThirdParty contained video_thumbextractor
[1342] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_height
[1343] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_image_width
[1344] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_baseline
[1345] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_dpi
[1346] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_optimize
[1347] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_progressive_mode
[1348] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_quality
[1349] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_jpeg_smooth
[1350] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_next_time
[1351] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_only_keyframe
[1352] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_processes_per_worker
[1353] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_threads
[1354] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_color
[1355] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_cols
[1356] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_margin
[1357] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_cols
[1358] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_max_rows
[1359] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_padding
[1360] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_rows
[1361] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_tile_sample_interval
[1362] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_filename
[1363] syn keyword ngxDirectiveThirdParty contained video_thumbextractor_video_second
[1364] 
[1365] " https://github.com/calio/iconv-nginx-module
[1366] syn keyword ngxDirectiveThirdParty contained iconv_buffer_size
[1367] syn keyword ngxDirectiveThirdParty contained iconv_filter
[1368] syn keyword ngxDirectiveThirdParty contained set_iconv
[1369] 
[1370] " https://github.com/baysao/nginx-let-module
[1371] syn keyword ngxDirectiveThirdParty contained let
[1372] 
[1373] " https://github.com/openresty/lua-nginx-module
[1374] syn keyword ngxDirectiveThirdParty contained access_by_lua
[1375] syn keyword ngxDirectiveThirdParty contained access_by_lua_block
[1376] syn keyword ngxDirectiveThirdParty contained access_by_lua_file
[1377] syn keyword ngxDirectiveThirdParty contained access_by_lua_no_postpone
[1378] syn keyword ngxDirectiveThirdParty contained balancer_by_lua_block
[1379] syn keyword ngxDirectiveThirdParty contained balancer_by_lua_file
[1380] syn keyword ngxDirectiveThirdParty contained body_filter_by_lua
[1381] syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_block
[1382] syn keyword ngxDirectiveThirdParty contained body_filter_by_lua_file
[1383] syn keyword ngxDirectiveThirdParty contained content_by_lua
[1384] syn keyword ngxDirectiveThirdParty contained content_by_lua_block
[1385] syn keyword ngxDirectiveThirdParty contained content_by_lua_file
[1386] syn keyword ngxDirectiveThirdParty contained exit_worker_by_lua_block
[1387] syn keyword ngxDirectiveThirdParty contained exit_worker_by_lua_file
[1388] syn keyword ngxDirectiveThirdParty contained header_filter_by_lua
[1389] syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_block
[1390] syn keyword ngxDirectiveThirdParty contained header_filter_by_lua_file
[1391] syn keyword ngxDirectiveThirdParty contained init_by_lua
[1392] syn keyword ngxDirectiveThirdParty contained init_by_lua_block
[1393] syn keyword ngxDirectiveThirdParty contained init_by_lua_file
[1394] syn keyword ngxDirectiveThirdParty contained init_worker_by_lua
[1395] syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_block
[1396] syn keyword ngxDirectiveThirdParty contained init_worker_by_lua_file
[1397] syn keyword ngxDirectiveThirdParty contained log_by_lua
[1398] syn keyword ngxDirectiveThirdParty contained log_by_lua_block
[1399] syn keyword ngxDirectiveThirdParty contained log_by_lua_file
[1400] syn keyword ngxDirectiveThirdParty contained lua_capture_error_log
[1401] syn keyword ngxDirectiveThirdParty contained lua_check_client_abort
[1402] syn keyword ngxDirectiveThirdParty contained lua_code_cache
[1403] syn keyword ngxDirectiveThirdParty contained lua_fake_shm
[1404] syn keyword ngxDirectiveThirdParty contained lua_http10_buffering
[1405] syn keyword ngxDirectiveThirdParty contained lua_load_resty_core
[1406] syn keyword ngxDirectiveThirdParty contained lua_malloc_trim
[1407] syn keyword ngxDirectiveThirdParty contained lua_max_pending_timers
[1408] syn keyword ngxDirectiveThirdParty contained lua_max_running_timers
[1409] syn keyword ngxDirectiveThirdParty contained lua_need_request_body
[1410] syn keyword ngxDirectiveThirdParty contained lua_package_cpath
[1411] syn keyword ngxDirectiveThirdParty contained lua_package_path
[1412] syn keyword ngxDirectiveThirdParty contained lua_regex_cache_max_entries
[1413] syn keyword ngxDirectiveThirdParty contained lua_regex_match_limit
[1414] syn keyword ngxDirectiveThirdParty contained lua_sa_restart
[1415] syn keyword ngxDirectiveThirdParty contained lua_shared_dict
[1416] syn keyword ngxDirectiveThirdParty contained lua_socket_buffer_size
[1417] syn keyword ngxDirectiveThirdParty contained lua_socket_connect_timeout
[1418] syn keyword ngxDirectiveThirdParty contained lua_socket_keepalive_timeout
[1419] syn keyword ngxDirectiveThirdParty contained lua_socket_log_errors
[1420] syn keyword ngxDirectiveThirdParty contained lua_socket_pool_size
[1421] syn keyword ngxDirectiveThirdParty contained lua_socket_read_timeout
[1422] syn keyword ngxDirectiveThirdParty contained lua_socket_send_lowat
[1423] syn keyword ngxDirectiveThirdParty contained lua_socket_send_timeout
[1424] syn keyword ngxDirectiveThirdParty contained lua_ssl_ciphers
[1425] syn keyword ngxDirectiveThirdParty contained lua_ssl_conf_command
[1426] syn keyword ngxDirectiveThirdParty contained lua_ssl_crl
[1427] syn keyword ngxDirectiveThirdParty contained lua_ssl_protocols
[1428] syn keyword ngxDirectiveThirdParty contained lua_ssl_trusted_certificate
[1429] syn keyword ngxDirectiveThirdParty contained lua_ssl_verify_depth
[1430] syn keyword ngxDirectiveThirdParty contained lua_thread_cache_max_entries
[1431] syn keyword ngxDirectiveThirdParty contained lua_transform_underscores_in_response_headers
[1432] syn keyword ngxDirectiveThirdParty contained lua_use_default_type
[1433] syn keyword ngxDirectiveThirdParty contained lua_worker_thread_vm_pool_size
[1434] syn keyword ngxDirectiveThirdParty contained rewrite_by_lua
[1435] syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_block
[1436] syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_file
[1437] syn keyword ngxDirectiveThirdParty contained rewrite_by_lua_no_postpone
[1438] syn keyword ngxDirectiveThirdParty contained server_rewrite_by_lua_block
[1439] syn keyword ngxDirectiveThirdParty contained server_rewrite_by_lua_file
[1440] syn keyword ngxDirectiveThirdParty contained set_by_lua
[1441] syn keyword ngxDirectiveThirdParty contained set_by_lua_block
[1442] syn keyword ngxDirectiveThirdParty contained set_by_lua_file
[1443] syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_block
[1444] syn keyword ngxDirectiveThirdParty contained ssl_certificate_by_lua_file
[1445] syn keyword ngxDirectiveThirdParty contained ssl_client_hello_by_lua_block
[1446] syn keyword ngxDirectiveThirdParty contained ssl_client_hello_by_lua_file
[1447] syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_block
[1448] syn keyword ngxDirectiveThirdParty contained ssl_session_fetch_by_lua_file
[1449] syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_block
[1450] syn keyword ngxDirectiveThirdParty contained ssl_session_store_by_lua_file
[1451] 
[1452] " https://github.com/Taymindis/nginx-link-function
[1453] syn keyword ngxDirectiveThirdParty contained ngx_link_func_add_prop
[1454] syn keyword ngxDirectiveThirdParty contained ngx_link_func_add_req_header
[1455] syn keyword ngxDirectiveThirdParty contained ngx_link_func_ca_cert
[1456] syn keyword ngxDirectiveThirdParty contained ngx_link_func_call
[1457] syn keyword ngxDirectiveThirdParty contained ngx_link_func_download_link_lib
[1458] syn keyword ngxDirectiveThirdParty contained ngx_link_func_lib
[1459] syn keyword ngxDirectiveThirdParty contained ngx_link_func_shm_size
[1460] syn keyword ngxDirectiveThirdParty contained ngx_link_func_subrequest
[1461] 
[1462] " https://github.com/openresty/memc-nginx-module
[1463] syn keyword ngxDirectiveThirdParty contained memc_buffer_size
[1464] syn keyword ngxDirectiveThirdParty contained memc_cmds_allowed
[1465] syn keyword ngxDirectiveThirdParty contained memc_connect_timeout
[1466] syn keyword ngxDirectiveThirdParty contained memc_flags_to_last_modified
[1467] syn keyword ngxDirectiveThirdParty contained memc_ignore_client_abort
[1468] syn keyword ngxDirectiveThirdParty contained memc_next_upstream
[1469] syn keyword ngxDirectiveThirdParty contained memc_pass
[1470] syn keyword ngxDirectiveThirdParty contained memc_read_timeout
[1471] syn keyword ngxDirectiveThirdParty contained memc_send_timeout
[1472] syn keyword ngxDirectiveThirdParty contained memc_upstream_fail_timeout
[1473] syn keyword ngxDirectiveThirdParty contained memc_upstream_max_fails
[1474] 
[1475] " https://github.com/SpiderLabs/ModSecurity-nginx
[1476] syn keyword ngxDirectiveThirdParty contained modsecurity
[1477] syn keyword ngxDirectiveThirdParty contained modsecurity_rules
[1478] syn keyword ngxDirectiveThirdParty contained modsecurity_rules_file
[1479] syn keyword ngxDirectiveThirdParty contained modsecurity_rules_remote
[1480] syn keyword ngxDirectiveThirdParty contained modsecurity_transaction_id
[1481] 
[1482] " https://github.com/nbs-system/naxsi
[1483] syn keyword ngxDirectiveThirdParty contained BasicRule
[1484] syn keyword ngxDirectiveThirdParty contained CheckRule
[1485] syn keyword ngxDirectiveThirdParty contained DeniedUrl
[1486] syn keyword ngxDirectiveThirdParty contained IgnoreCIDR
[1487] syn keyword ngxDirectiveThirdParty contained IgnoreIP
[1488] syn keyword ngxDirectiveThirdParty contained LearningMode
[1489] syn keyword ngxDirectiveThirdParty contained LibInjectionSql
[1490] syn keyword ngxDirectiveThirdParty contained LibInjectionXss
[1491] syn keyword ngxDirectiveThirdParty contained MainRule
[1492] syn keyword ngxDirectiveThirdParty contained NaxsiLogFile
[1493] syn keyword ngxDirectiveThirdParty contained SecRulesDisabled
[1494] syn keyword ngxDirectiveThirdParty contained SecRulesEnabled
[1495] syn keyword ngxDirectiveThirdParty contained basic_rule
[1496] syn keyword ngxDirectiveThirdParty contained check_rule
[1497] syn keyword ngxDirectiveThirdParty contained denied_url
[1498] syn keyword ngxDirectiveThirdParty contained learning_mode
[1499] syn keyword ngxDirectiveThirdParty contained libinjection_sql
[1500] syn keyword ngxDirectiveThirdParty contained libinjection_xss
[1501] syn keyword ngxDirectiveThirdParty contained main_rule
[1502] syn keyword ngxDirectiveThirdParty contained naxsi_log
[1503] syn keyword ngxDirectiveThirdParty contained rules_disabled
[1504] syn keyword ngxDirectiveThirdParty contained rules_enabled
[1505] 
[1506] " https://github.com/opentracing-contrib/nginx-opentracing
[1507] syn keyword ngxDirectiveThirdParty contained opentracing
[1508] syn keyword ngxDirectiveThirdParty contained opentracing_fastcgi_propagate_context
[1509] syn keyword ngxDirectiveThirdParty contained opentracing_grpc_propagate_context
[1510] syn keyword ngxDirectiveThirdParty contained opentracing_load_tracer
[1511] syn keyword ngxDirectiveThirdParty contained opentracing_location_operation_name
[1512] syn keyword ngxDirectiveThirdParty contained opentracing_operation_name
[1513] syn keyword ngxDirectiveThirdParty contained opentracing_propagate_context
[1514] syn keyword ngxDirectiveThirdParty contained opentracing_tag
[1515] syn keyword ngxDirectiveThirdParty contained opentracing_trace_locations
[1516] syn keyword ngxDirectiveThirdParty contained opentracing_trust_incoming_span
[1517] 
[1518] " https://github.com/phusion/passenger
[1519] syn keyword ngxDirectiveThirdParty contained passenger_abort_on_startup_error
[1520] syn keyword ngxDirectiveThirdParty contained passenger_abort_websockets_on_process_shutdown
[1521] syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_auth_type
[1522] syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_password
[1523] syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_url
[1524] syn keyword ngxDirectiveThirdParty contained passenger_admin_panel_username
[1525] syn keyword ngxDirectiveThirdParty contained passenger_analytics_log_group
[1526] syn keyword ngxDirectiveThirdParty contained passenger_analytics_log_user
[1527] syn keyword ngxDirectiveThirdParty contained passenger_anonymous_telemetry_proxy
[1528] syn keyword ngxDirectiveThirdParty contained passenger_app_env
[1529] syn keyword ngxDirectiveThirdParty contained passenger_app_file_descriptor_ulimit
[1530] syn keyword ngxDirectiveThirdParty contained passenger_app_group_name
[1531] syn keyword ngxDirectiveThirdParty contained passenger_app_log_file
[1532] syn keyword ngxDirectiveThirdParty contained passenger_app_rights
[1533] syn keyword ngxDirectiveThirdParty contained passenger_app_root
[1534] syn keyword ngxDirectiveThirdParty contained passenger_app_start_command
[1535] syn keyword ngxDirectiveThirdParty contained passenger_app_type
[1536] syn keyword ngxDirectiveThirdParty contained passenger_base_uri
[1537] syn keyword ngxDirectiveThirdParty contained passenger_buffer_response
[1538] syn keyword ngxDirectiveThirdParty contained passenger_buffer_size
[1539] syn keyword ngxDirectiveThirdParty contained passenger_buffer_upload
[1540] syn keyword ngxDirectiveThirdParty contained passenger_buffers
[1541] syn keyword ngxDirectiveThirdParty contained passenger_busy_buffers_size
[1542] syn keyword ngxDirectiveThirdParty contained passenger_concurrency_model
[1543] syn keyword ngxDirectiveThirdParty contained passenger_core_file_descriptor_ulimit
[1544] syn keyword ngxDirectiveThirdParty contained passenger_ctl
[1545] syn keyword ngxDirectiveThirdParty contained passenger_data_buffer_dir
[1546] syn keyword ngxDirectiveThirdParty contained passenger_debug_log_file
[1547] syn keyword ngxDirectiveThirdParty contained passenger_debugger
[1548] syn keyword ngxDirectiveThirdParty contained passenger_default_group
[1549] syn keyword ngxDirectiveThirdParty contained passenger_default_user
[1550] syn keyword ngxDirectiveThirdParty contained passenger_direct_instance_request_address
[1551] syn keyword ngxDirectiveThirdParty contained passenger_disable_anonymous_telemetry
[1552] syn keyword ngxDirectiveThirdParty contained passenger_disable_log_prefix
[1553] syn keyword ngxDirectiveThirdParty contained passenger_disable_security_update_check
[1554] syn keyword ngxDirectiveThirdParty contained passenger_document_root
[1555] syn keyword ngxDirectiveThirdParty contained passenger_dump_config_manifest
[1556] syn keyword ngxDirectiveThirdParty contained passenger_enabled
[1557] syn keyword ngxDirectiveThirdParty contained passenger_env_var
[1558] syn keyword ngxDirectiveThirdParty contained passenger_file_descriptor_log_file
[1559] syn keyword ngxDirectiveThirdParty contained passenger_fly_with
[1560] syn keyword ngxDirectiveThirdParty contained passenger_force_max_concurrent_requests_per_process
[1561] syn keyword ngxDirectiveThirdParty contained passenger_friendly_error_pages
[1562] syn keyword ngxDirectiveThirdParty contained passenger_group
[1563] syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_bucket_size
[1564] syn keyword ngxDirectiveThirdParty contained passenger_headers_hash_max_size
[1565] syn keyword ngxDirectiveThirdParty contained passenger_ignore_client_abort
[1566] syn keyword ngxDirectiveThirdParty contained passenger_ignore_headers
[1567] syn keyword ngxDirectiveThirdParty contained passenger_instance_registry_dir
[1568] syn keyword ngxDirectiveThirdParty contained passenger_intercept_errors
[1569] syn keyword ngxDirectiveThirdParty contained passenger_load_shell_envvars
[1570] syn keyword ngxDirectiveThirdParty contained passenger_log_file
[1571] syn keyword ngxDirectiveThirdParty contained passenger_log_level
[1572] syn keyword ngxDirectiveThirdParty contained passenger_max_instances
[1573] syn keyword ngxDirectiveThirdParty contained passenger_max_instances_per_app
[1574] syn keyword ngxDirectiveThirdParty contained passenger_max_pool_size
[1575] syn keyword ngxDirectiveThirdParty contained passenger_max_preloader_idle_time
[1576] syn keyword ngxDirectiveThirdParty contained passenger_max_request_queue_size
[1577] syn keyword ngxDirectiveThirdParty contained passenger_max_request_queue_time
[1578] syn keyword ngxDirectiveThirdParty contained passenger_max_request_time
[1579] syn keyword ngxDirectiveThirdParty contained passenger_max_requests
[1580] syn keyword ngxDirectiveThirdParty contained passenger_memory_limit
[1581] syn keyword ngxDirectiveThirdParty contained passenger_meteor_app_settings
[1582] syn keyword ngxDirectiveThirdParty contained passenger_min_instances
[1583] syn keyword ngxDirectiveThirdParty contained passenger_monitor_log_file
[1584] syn keyword ngxDirectiveThirdParty contained passenger_nodejs
[1585] syn keyword ngxDirectiveThirdParty contained passenger_pass_header
[1586] syn keyword ngxDirectiveThirdParty contained passenger_pool_idle_time
[1587] syn keyword ngxDirectiveThirdParty contained passenger_pre_start
[1588] syn keyword ngxDirectiveThirdParty contained passenger_preload_bundler
[1589] syn keyword ngxDirectiveThirdParty contained passenger_python
[1590] syn keyword ngxDirectiveThirdParty contained passenger_read_timeout
[1591] syn keyword ngxDirectiveThirdParty contained passenger_request_buffering
[1592] syn keyword ngxDirectiveThirdParty contained passenger_request_queue_overflow_status_code
[1593] syn keyword ngxDirectiveThirdParty contained passenger_resist_deployment_errors
[1594] syn keyword ngxDirectiveThirdParty contained passenger_response_buffer_high_watermark
[1595] syn keyword ngxDirectiveThirdParty contained passenger_restart_dir
[1596] syn keyword ngxDirectiveThirdParty contained passenger_rolling_restarts
[1597] syn keyword ngxDirectiveThirdParty contained passenger_root
[1598] syn keyword ngxDirectiveThirdParty contained passenger_ruby
[1599] syn keyword ngxDirectiveThirdParty contained passenger_security_update_check_proxy
[1600] syn keyword ngxDirectiveThirdParty contained passenger_set_header
[1601] syn keyword ngxDirectiveThirdParty contained passenger_show_version_in_header
[1602] syn keyword ngxDirectiveThirdParty contained passenger_socket_backlog
[1603] syn keyword ngxDirectiveThirdParty contained passenger_spawn_dir
[1604] syn keyword ngxDirectiveThirdParty contained passenger_spawn_exception_status_code
[1605] syn keyword ngxDirectiveThirdParty contained passenger_spawn_method
[1606] syn keyword ngxDirectiveThirdParty contained passenger_start_timeout
[1607] syn keyword ngxDirectiveThirdParty contained passenger_startup_file
[1608] syn keyword ngxDirectiveThirdParty contained passenger_stat_throttle_rate
[1609] syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions
[1610] syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions_cookie_attributes
[1611] syn keyword ngxDirectiveThirdParty contained passenger_sticky_sessions_cookie_name
[1612] syn keyword ngxDirectiveThirdParty contained passenger_temp_path
[1613] syn keyword ngxDirectiveThirdParty contained passenger_thread_count
[1614] syn keyword ngxDirectiveThirdParty contained passenger_turbocaching
[1615] syn keyword ngxDirectiveThirdParty contained passenger_use_global_queue
[1616] syn keyword ngxDirectiveThirdParty contained passenger_user
[1617] syn keyword ngxDirectiveThirdParty contained passenger_user_switching
[1618] syn keyword ngxDirectiveThirdParty contained passenger_vary_turbocache_by_cookie
[1619] syn keyword ngxDirectiveThirdParty contained rack_env
[1620] syn keyword ngxDirectiveThirdParty contained rails_app_spawner_idle_time
[1621] syn keyword ngxDirectiveThirdParty contained rails_env
[1622] syn keyword ngxDirectiveThirdParty contained rails_framework_spawner_idle_time
[1623] syn keyword ngxDirectiveThirdParty contained rails_spawn_method
[1624] syn keyword ngxDirectiveThirdParty contained union_station_filter
[1625] syn keyword ngxDirectiveThirdParty contained union_station_gateway_address
[1626] syn keyword ngxDirectiveThirdParty contained union_station_gateway_cert
[1627] syn keyword ngxDirectiveThirdParty contained union_station_gateway_port
[1628] syn keyword ngxDirectiveThirdParty contained union_station_key
[1629] syn keyword ngxDirectiveThirdParty contained union_station_proxy_address
[1630] syn keyword ngxDirectiveThirdParty contained union_station_support
[1631] 
[1632] " https://github.com/konstruxi/ngx_postgres
[1633] syn keyword ngxDirectiveThirdParty contained postgres_connect_timeout
[1634] syn keyword ngxDirectiveThirdParty contained postgres_escape
[1635] syn keyword ngxDirectiveThirdParty contained postgres_keepalive
[1636] syn keyword ngxDirectiveThirdParty contained postgres_output
[1637] syn keyword ngxDirectiveThirdParty contained postgres_pass
[1638] syn keyword ngxDirectiveThirdParty contained postgres_query
[1639] syn keyword ngxDirectiveThirdParty contained postgres_result_timeout
[1640] syn keyword ngxDirectiveThirdParty contained postgres_rewrite
[1641] syn keyword ngxDirectiveThirdParty contained postgres_server
[1642] syn keyword ngxDirectiveThirdParty contained postgres_set
[1643] 
[1644] " https://github.com/openresty/rds-csv-nginx-module
[1645] syn keyword ngxDirectiveThirdParty contained rds_csv
[1646] syn keyword ngxDirectiveThirdParty contained rds_csv_buffer_size
[1647] syn keyword ngxDirectiveThirdParty contained rds_csv_content_type
[1648] syn keyword ngxDirectiveThirdParty contained rds_csv_field_name_header
[1649] syn keyword ngxDirectiveThirdParty contained rds_csv_field_separator
[1650] syn keyword ngxDirectiveThirdParty contained rds_csv_row_terminator
[1651] 
[1652] " https://github.com/openresty/rds-json-nginx-module
[1653] syn keyword ngxDirectiveThirdParty contained rds_json
[1654] syn keyword ngxDirectiveThirdParty contained rds_json_buffer_size
[1655] syn keyword ngxDirectiveThirdParty contained rds_json_content_type
[1656] syn keyword ngxDirectiveThirdParty contained rds_json_errcode_key
[1657] syn keyword ngxDirectiveThirdParty contained rds_json_errstr_key
[1658] syn keyword ngxDirectiveThirdParty contained rds_json_format
[1659] syn keyword ngxDirectiveThirdParty contained rds_json_ret
[1660] syn keyword ngxDirectiveThirdParty contained rds_json_root
[1661] syn keyword ngxDirectiveThirdParty contained rds_json_success_property
[1662] syn keyword ngxDirectiveThirdParty contained rds_json_user_property
[1663] 
[1664] " https://github.com/openresty/redis2-nginx-module
[1665] syn keyword ngxDirectiveThirdParty contained redis2_bind
[1666] syn keyword ngxDirectiveThirdParty contained redis2_buffer_size
[1667] syn keyword ngxDirectiveThirdParty contained redis2_connect_timeout
[1668] syn keyword ngxDirectiveThirdParty contained redis2_literal_raw_query
[1669] syn keyword ngxDirectiveThirdParty contained redis2_next_upstream
[1670] syn keyword ngxDirectiveThirdParty contained redis2_pass
[1671] syn keyword ngxDirectiveThirdParty contained redis2_query
[1672] syn keyword ngxDirectiveThirdParty contained redis2_raw_queries
[1673] syn keyword ngxDirectiveThirdParty contained redis2_raw_query
[1674] syn keyword ngxDirectiveThirdParty contained redis2_read_timeout
[1675] syn keyword ngxDirectiveThirdParty contained redis2_send_timeout
[1676] 
[1677] " https://github.com/arut/nginx-rtmp-module
[1678] syn keyword ngxDirectiveThirdParty contained ack_window
[1679] syn keyword ngxDirectiveThirdParty contained application
[1680] syn keyword ngxDirectiveThirdParty contained buffer
[1681] syn keyword ngxDirectiveThirdParty contained buflen
[1682] syn keyword ngxDirectiveThirdParty contained busy
[1683] syn keyword ngxDirectiveThirdParty contained chunk_size
[1684] syn keyword ngxDirectiveThirdParty contained dash
[1685] syn keyword ngxDirectiveThirdParty contained dash_cleanup
[1686] syn keyword ngxDirectiveThirdParty contained dash_fragment
[1687] syn keyword ngxDirectiveThirdParty contained dash_nested
[1688] syn keyword ngxDirectiveThirdParty contained dash_path
[1689] syn keyword ngxDirectiveThirdParty contained dash_playlist_length
[1690] syn keyword ngxDirectiveThirdParty contained drop_idle_publisher
[1691] syn keyword ngxDirectiveThirdParty contained exec
[1692] syn keyword ngxDirectiveThirdParty contained exec_block
[1693] syn keyword ngxDirectiveThirdParty contained exec_kill_signal
[1694] syn keyword ngxDirectiveThirdParty contained exec_options
[1695] syn keyword ngxDirectiveThirdParty contained exec_play
[1696] syn keyword ngxDirectiveThirdParty contained exec_play_done
[1697] syn keyword ngxDirectiveThirdParty contained exec_publish
[1698] syn keyword ngxDirectiveThirdParty contained exec_publish_done
[1699] syn keyword ngxDirectiveThirdParty contained exec_pull
[1700] syn keyword ngxDirectiveThirdParty contained exec_push
[1701] syn keyword ngxDirectiveThirdParty contained exec_record_done
[1702] syn keyword ngxDirectiveThirdParty contained exec_static
[1703] syn keyword ngxDirectiveThirdParty contained hls_audio_buffer_size
[1704] syn keyword ngxDirectiveThirdParty contained hls_base_url
[1705] syn keyword ngxDirectiveThirdParty contained hls_cleanup
[1706] syn keyword ngxDirectiveThirdParty contained hls_continuous
[1707] syn keyword ngxDirectiveThirdParty contained hls_fragment_naming
[1708] syn keyword ngxDirectiveThirdParty contained hls_fragment_naming_granularity
[1709] syn keyword ngxDirectiveThirdParty contained hls_fragment_slicing
[1710] syn keyword ngxDirectiveThirdParty contained hls_fragments_per_key
[1711] syn keyword ngxDirectiveThirdParty contained hls_key_path
[1712] syn keyword ngxDirectiveThirdParty contained hls_key_url
[1713] syn keyword ngxDirectiveThirdParty contained hls_keys
[1714] syn keyword ngxDirectiveThirdParty contained hls_max_audio_delay
[1715] syn keyword ngxDirectiveThirdParty contained hls_max_fragment
[1716] syn keyword ngxDirectiveThirdParty contained hls_muxdelay
[1717] syn keyword ngxDirectiveThirdParty contained hls_nested
[1718] syn keyword ngxDirectiveThirdParty contained hls_path
[1719] syn keyword ngxDirectiveThirdParty contained hls_playlist_length
[1720] syn keyword ngxDirectiveThirdParty contained hls_sync
[1721] syn keyword ngxDirectiveThirdParty contained hls_type
[1722] syn keyword ngxDirectiveThirdParty contained hls_variant
[1723] syn keyword ngxDirectiveThirdParty contained idle_streams
[1724] syn keyword ngxDirectiveThirdParty contained interleave
[1725] syn keyword ngxDirectiveThirdParty contained live
[1726] syn keyword ngxDirectiveThirdParty contained max_connections
[1727] syn keyword ngxDirectiveThirdParty contained max_message
[1728] syn keyword ngxDirectiveThirdParty contained max_streams
[1729] syn keyword ngxDirectiveThirdParty contained meta
[1730] syn keyword ngxDirectiveThirdParty contained netcall_buffer
[1731] syn keyword ngxDirectiveThirdParty contained netcall_timeout
[1732] syn keyword ngxDirectiveThirdParty contained notify_method
[1733] syn keyword ngxDirectiveThirdParty contained notify_relay_redirect
[1734] syn keyword ngxDirectiveThirdParty contained notify_update_strict
[1735] syn keyword ngxDirectiveThirdParty contained notify_update_timeout
[1736] syn keyword ngxDirectiveThirdParty contained on_connect
[1737] syn keyword ngxDirectiveThirdParty contained on_disconnect
[1738] syn keyword ngxDirectiveThirdParty contained on_done
[1739] syn keyword ngxDirectiveThirdParty contained on_play
[1740] syn keyword ngxDirectiveThirdParty contained on_play_done
[1741] syn keyword ngxDirectiveThirdParty contained on_publish
[1742] syn keyword ngxDirectiveThirdParty contained on_publish_done
[1743] syn keyword ngxDirectiveThirdParty contained on_record_done
[1744] syn keyword ngxDirectiveThirdParty contained on_update
[1745] syn keyword ngxDirectiveThirdParty contained out_cork
[1746] syn keyword ngxDirectiveThirdParty contained out_queue
[1747] syn keyword ngxDirectiveThirdParty contained ping
[1748] syn keyword ngxDirectiveThirdParty contained ping_timeout
[1749] syn keyword ngxDirectiveThirdParty contained play
[1750] syn keyword ngxDirectiveThirdParty contained play_local_path
[1751] syn keyword ngxDirectiveThirdParty contained play_restart
[1752] syn keyword ngxDirectiveThirdParty contained play_temp_path
[1753] syn keyword ngxDirectiveThirdParty contained play_time_fix
[1754] syn keyword ngxDirectiveThirdParty contained publish_notify
[1755] syn keyword ngxDirectiveThirdParty contained publish_time_fix
[1756] syn keyword ngxDirectiveThirdParty contained pull
[1757] syn keyword ngxDirectiveThirdParty contained pull_reconnect
[1758] syn keyword ngxDirectiveThirdParty contained push
[1759] syn keyword ngxDirectiveThirdParty contained push_reconnect
[1760] syn keyword ngxDirectiveThirdParty contained record
[1761] syn keyword ngxDirectiveThirdParty contained record_append
[1762] syn keyword ngxDirectiveThirdParty contained record_interval
[1763] syn keyword ngxDirectiveThirdParty contained record_lock
[1764] syn keyword ngxDirectiveThirdParty contained record_max_frames
[1765] syn keyword ngxDirectiveThirdParty contained record_max_size
[1766] syn keyword ngxDirectiveThirdParty contained record_notify
[1767] syn keyword ngxDirectiveThirdParty contained record_path
[1768] syn keyword ngxDirectiveThirdParty contained record_suffix
[1769] syn keyword ngxDirectiveThirdParty contained record_unique
[1770] syn keyword ngxDirectiveThirdParty contained recorder
[1771] syn keyword ngxDirectiveThirdParty contained relay_buffer
[1772] syn keyword ngxDirectiveThirdParty contained respawn
[1773] syn keyword ngxDirectiveThirdParty contained respawn_timeout
[1774] syn keyword ngxDirectiveThirdParty contained rtmp
[1775] syn keyword ngxDirectiveThirdParty contained rtmp_auto_push
[1776] syn keyword ngxDirectiveThirdParty contained rtmp_auto_push_reconnect
[1777] syn keyword ngxDirectiveThirdParty contained rtmp_control
[1778] syn keyword ngxDirectiveThirdParty contained rtmp_socket_dir
[1779] syn keyword ngxDirectiveThirdParty contained rtmp_stat
[1780] syn keyword ngxDirectiveThirdParty contained rtmp_stat_stylesheet
[1781] syn keyword ngxDirectiveThirdParty contained session_relay
[1782] syn keyword ngxDirectiveThirdParty contained so_keepalive
[1783] syn keyword ngxDirectiveThirdParty contained stream_buckets
[1784] syn keyword ngxDirectiveThirdParty contained sync
[1785] syn keyword ngxDirectiveThirdParty contained wait_key
[1786] syn keyword ngxDirectiveThirdParty contained wait_video
[1787] 
[1788] " https://github.com/openresty/set-misc-nginx-module
[1789] syn keyword ngxDirectiveThirdParty contained set_base32_alphabet
[1790] syn keyword ngxDirectiveThirdParty contained set_base32_padding
[1791] syn keyword ngxDirectiveThirdParty contained set_decode_base32
[1792] syn keyword ngxDirectiveThirdParty contained set_decode_base64
[1793] syn keyword ngxDirectiveThirdParty contained set_decode_base64url
[1794] syn keyword ngxDirectiveThirdParty contained set_decode_hex
[1795] syn keyword ngxDirectiveThirdParty contained set_encode_base32
[1796] syn keyword ngxDirectiveThirdParty contained set_encode_base64
[1797] syn keyword ngxDirectiveThirdParty contained set_encode_base64url
[1798] syn keyword ngxDirectiveThirdParty contained set_encode_hex
[1799] syn keyword ngxDirectiveThirdParty contained set_escape_uri
[1800] syn keyword ngxDirectiveThirdParty contained set_formatted_gmt_time
[1801] syn keyword ngxDirectiveThirdParty contained set_formatted_local_time
[1802] syn keyword ngxDirectiveThirdParty contained set_hashed_upstream
[1803] syn keyword ngxDirectiveThirdParty contained set_hmac_sha1
[1804] syn keyword ngxDirectiveThirdParty contained set_hmac_sha256
[1805] syn keyword ngxDirectiveThirdParty contained set_if_empty
[1806] syn keyword ngxDirectiveThirdParty contained set_local_today
[1807] syn keyword ngxDirectiveThirdParty contained set_md5
[1808] syn keyword ngxDirectiveThirdParty contained set_misc_base32_padding
[1809] syn keyword ngxDirectiveThirdParty contained set_quote_json_str
[1810] syn keyword ngxDirectiveThirdParty contained set_quote_pgsql_str
[1811] syn keyword ngxDirectiveThirdParty contained set_quote_sql_str
[1812] syn keyword ngxDirectiveThirdParty contained set_random
[1813] syn keyword ngxDirectiveThirdParty contained set_rotate
[1814] syn keyword ngxDirectiveThirdParty contained set_secure_random_alphanum
[1815] syn keyword ngxDirectiveThirdParty contained set_secure_random_lcalpha
[1816] syn keyword ngxDirectiveThirdParty contained set_sha1
[1817] syn keyword ngxDirectiveThirdParty contained set_unescape_uri
[1818] 
[1819] " https://github.com/sflow/nginx-sflow-module
[1820] syn keyword ngxDirectiveThirdParty contained sflow
[1821] 
[1822] " https://github.com/nginx-shib/nginx-http-shibboleth
[1823] syn keyword ngxDirectiveThirdParty contained shib_request
[1824] syn keyword ngxDirectiveThirdParty contained shib_request_set
[1825] syn keyword ngxDirectiveThirdParty contained shib_request_use_headers
[1826] 
[1827] " https://github.com/baysao/ngx_slowfs_cache
[1828] syn keyword ngxDirectiveThirdParty contained slowfs_big_file_size
[1829] syn keyword ngxDirectiveThirdParty contained slowfs_cache
[1830] syn keyword ngxDirectiveThirdParty contained slowfs_cache_key
[1831] syn keyword ngxDirectiveThirdParty contained slowfs_cache_min_uses
[1832] syn keyword ngxDirectiveThirdParty contained slowfs_cache_path
[1833] syn keyword ngxDirectiveThirdParty contained slowfs_cache_purge
[1834] syn keyword ngxDirectiveThirdParty contained slowfs_cache_valid
[1835] syn keyword ngxDirectiveThirdParty contained slowfs_temp_path
[1836] 
[1837] " https://github.com/kawakibi/ngx_small_light
[1838] syn keyword ngxDirectiveThirdParty contained small_light
[1839] syn keyword ngxDirectiveThirdParty contained small_light_buffer
[1840] syn keyword ngxDirectiveThirdParty contained small_light_getparam_mode
[1841] syn keyword ngxDirectiveThirdParty contained small_light_imlib2_temp_dir
[1842] syn keyword ngxDirectiveThirdParty contained small_light_material_dir
[1843] syn keyword ngxDirectiveThirdParty contained small_light_pattern_define
[1844] syn keyword ngxDirectiveThirdParty contained small_light_radius_max
[1845] syn keyword ngxDirectiveThirdParty contained small_light_sigma_max
[1846] 
[1847] " https://github.com/openresty/srcache-nginx-module
[1848] syn keyword ngxDirectiveThirdParty contained srcache_buffer
[1849] syn keyword ngxDirectiveThirdParty contained srcache_default_expire
[1850] syn keyword ngxDirectiveThirdParty contained srcache_fetch
[1851] syn keyword ngxDirectiveThirdParty contained srcache_fetch_skip
[1852] syn keyword ngxDirectiveThirdParty contained srcache_header_buffer_size
[1853] syn keyword ngxDirectiveThirdParty contained srcache_ignore_content_encoding
[1854] syn keyword ngxDirectiveThirdParty contained srcache_max_expire
[1855] syn keyword ngxDirectiveThirdParty contained srcache_methods
[1856] syn keyword ngxDirectiveThirdParty contained srcache_request_cache_control
[1857] syn keyword ngxDirectiveThirdParty contained srcache_response_cache_control
[1858] syn keyword ngxDirectiveThirdParty contained srcache_store
[1859] syn keyword ngxDirectiveThirdParty contained srcache_store_hide_header
[1860] syn keyword ngxDirectiveThirdParty contained srcache_store_max_size
[1861] syn keyword ngxDirectiveThirdParty contained srcache_store_no_cache
[1862] syn keyword ngxDirectiveThirdParty contained srcache_store_no_store
[1863] syn keyword ngxDirectiveThirdParty contained srcache_store_pass_header
[1864] syn keyword ngxDirectiveThirdParty contained srcache_store_private
[1865] syn keyword ngxDirectiveThirdParty contained srcache_store_ranges
[1866] syn keyword ngxDirectiveThirdParty contained srcache_store_skip
[1867] syn keyword ngxDirectiveThirdParty contained srcache_store_statuses
[1868] 
[1869] " https://github.com/kaltura/nginx-vod-module
[1870] syn keyword ngxDirectiveThirdParty contained vod
[1871] syn keyword ngxDirectiveThirdParty contained vod_align_segments_to_key_frames
[1872] syn keyword ngxDirectiveThirdParty contained vod_apply_dynamic_mapping
[1873] syn keyword ngxDirectiveThirdParty contained vod_base_url
[1874] syn keyword ngxDirectiveThirdParty contained vod_bootstrap_segment_durations
[1875] syn keyword ngxDirectiveThirdParty contained vod_cache_buffer_size
[1876] syn keyword ngxDirectiveThirdParty contained vod_clip_from_param_name
[1877] syn keyword ngxDirectiveThirdParty contained vod_clip_to_param_name
[1878] syn keyword ngxDirectiveThirdParty contained vod_drm_clear_lead_segment_count
[1879] syn keyword ngxDirectiveThirdParty contained vod_drm_enabled
[1880] syn keyword ngxDirectiveThirdParty contained vod_drm_info_cache
[1881] syn keyword ngxDirectiveThirdParty contained vod_drm_max_info_length
[1882] syn keyword ngxDirectiveThirdParty contained vod_drm_request_uri
[1883] syn keyword ngxDirectiveThirdParty contained vod_drm_single_key
[1884] syn keyword ngxDirectiveThirdParty contained vod_drm_upstream_location
[1885] syn keyword ngxDirectiveThirdParty contained vod_dynamic_clip_map_uri
[1886] syn keyword ngxDirectiveThirdParty contained vod_dynamic_mapping_cache
[1887] syn keyword ngxDirectiveThirdParty contained vod_encryption_iv_seed
[1888] syn keyword ngxDirectiveThirdParty contained vod_expires
[1889] syn keyword ngxDirectiveThirdParty contained vod_expires_live
[1890] syn keyword ngxDirectiveThirdParty contained vod_expires_live_time_dependent
[1891] syn keyword ngxDirectiveThirdParty contained vod_fallback_upstream_location
[1892] syn keyword ngxDirectiveThirdParty contained vod_force_continuous_timestamps
[1893] syn keyword ngxDirectiveThirdParty contained vod_force_playlist_type_vod
[1894] syn keyword ngxDirectiveThirdParty contained vod_force_sequence_index
[1895] syn keyword ngxDirectiveThirdParty contained vod_gop_look_ahead
[1896] syn keyword ngxDirectiveThirdParty contained vod_gop_look_behind
[1897] syn keyword ngxDirectiveThirdParty contained vod_ignore_edit_list
[1898] syn keyword ngxDirectiveThirdParty contained vod_initial_read_size
[1899] syn keyword ngxDirectiveThirdParty contained vod_lang_param_name
[1900] syn keyword ngxDirectiveThirdParty contained vod_last_modified
[1901] syn keyword ngxDirectiveThirdParty contained vod_last_modified_types
[1902] syn keyword ngxDirectiveThirdParty contained vod_live_mapping_cache
[1903] syn keyword ngxDirectiveThirdParty contained vod_live_response_cache
[1904] syn keyword ngxDirectiveThirdParty contained vod_live_window_duration
[1905] syn keyword ngxDirectiveThirdParty contained vod_manifest_duration_policy
[1906] syn keyword ngxDirectiveThirdParty contained vod_manifest_segment_durations_mode
[1907] syn keyword ngxDirectiveThirdParty contained vod_mapping_cache
[1908] syn keyword ngxDirectiveThirdParty contained vod_max_frame_count
[1909] syn keyword ngxDirectiveThirdParty contained vod_max_frames_size
[1910] syn keyword ngxDirectiveThirdParty contained vod_max_mapping_response_size
[1911] syn keyword ngxDirectiveThirdParty contained vod_max_metadata_size
[1912] syn keyword ngxDirectiveThirdParty contained vod_max_upstream_headers_size
[1913] syn keyword ngxDirectiveThirdParty contained vod_media_set_map_uri
[1914] syn keyword ngxDirectiveThirdParty contained vod_media_set_override_json
[1915] syn keyword ngxDirectiveThirdParty contained vod_metadata_cache
[1916] syn keyword ngxDirectiveThirdParty contained vod_min_single_nalu_per_frame_segment
[1917] syn keyword ngxDirectiveThirdParty contained vod_mode
[1918] syn keyword ngxDirectiveThirdParty contained vod_multi_uri_suffix
[1919] syn keyword ngxDirectiveThirdParty contained vod_notification_uri
[1920] syn keyword ngxDirectiveThirdParty contained vod_open_file_thread_pool
[1921] syn keyword ngxDirectiveThirdParty contained vod_output_buffer_pool
[1922] syn keyword ngxDirectiveThirdParty contained vod_parse_hdlr_name
[1923] syn keyword ngxDirectiveThirdParty contained vod_parse_udta_name
[1924] syn keyword ngxDirectiveThirdParty contained vod_path_response_postfix
[1925] syn keyword ngxDirectiveThirdParty contained vod_path_response_prefix
[1926] syn keyword ngxDirectiveThirdParty contained vod_performance_counters
[1927] syn keyword ngxDirectiveThirdParty contained vod_proxy_header_name
[1928] syn keyword ngxDirectiveThirdParty contained vod_proxy_header_value
[1929] syn keyword ngxDirectiveThirdParty contained vod_redirect_segments_url
[1930] syn keyword ngxDirectiveThirdParty contained vod_remote_upstream_location
[1931] syn keyword ngxDirectiveThirdParty contained vod_response_cache
[1932] syn keyword ngxDirectiveThirdParty contained vod_secret_key
[1933] syn keyword ngxDirectiveThirdParty contained vod_segment_count_policy
[1934] syn keyword ngxDirectiveThirdParty contained vod_segment_duration
[1935] syn keyword ngxDirectiveThirdParty contained vod_segment_max_frame_count
[1936] syn keyword ngxDirectiveThirdParty contained vod_segments_base_url
[1937] syn keyword ngxDirectiveThirdParty contained vod_source_clip_map_uri
[1938] syn keyword ngxDirectiveThirdParty contained vod_speed_param_name
[1939] syn keyword ngxDirectiveThirdParty contained vod_status
[1940] syn keyword ngxDirectiveThirdParty contained vod_time_shift_param_name
[1941] syn keyword ngxDirectiveThirdParty contained vod_tracks_param_name
[1942] syn keyword ngxDirectiveThirdParty contained vod_upstream_extra_args
[1943] syn keyword ngxDirectiveThirdParty contained vod_upstream_location
[1944] 
[1945] " https://github.com/vozlt/nginx-module-vts
[1946] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status
[1947] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_average_method
[1948] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_bypass_limit
[1949] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_bypass_stats
[1950] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display
[1951] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_format
[1952] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_jsonp
[1953] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_display_sum_key
[1954] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_dump
[1955] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter
[1956] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_host
[1957] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_by_set_key
[1958] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_check_duplicate
[1959] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_filter_max_node
[1960] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_histogram_buckets
[1961] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit
[1962] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_check_duplicate
[1963] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic
[1964] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_limit_traffic_by_set_key
[1965] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_set_by_filter
[1966] syn keyword ngxDirectiveThirdParty contained vhost_traffic_status_zone
[1967] 
[1968] " https://github.com/openresty/xss-nginx-module
[1969] syn keyword ngxDirectiveThirdParty contained xss_callback_arg
[1970] syn keyword ngxDirectiveThirdParty contained xss_check_status
[1971] syn keyword ngxDirectiveThirdParty contained xss_get
[1972] syn keyword ngxDirectiveThirdParty contained xss_input_types
[1973] syn keyword ngxDirectiveThirdParty contained xss_output_type
[1974] syn keyword ngxDirectiveThirdParty contained xss_override_status
[1975] 
[1976] " https://github.com/tg123/websockify-nginx-module
[1977] syn keyword ngxDirectiveThirdParty contained websockify_buffer_size
[1978] syn keyword ngxDirectiveThirdParty contained websockify_connect_timeout
[1979] syn keyword ngxDirectiveThirdParty contained websockify_pass
[1980] syn keyword ngxDirectiveThirdParty contained websockify_read_timeout
[1981] syn keyword ngxDirectiveThirdParty contained websockify_send_timeout
[1982] 
[1983] " highlight
[1984] 
[1985] hi def link ngxComment Comment
[1986] hi def link ngxParamComment Comment
[1987] hi def link ngxListenComment Comment
[1988] hi def link ngxVariable Identifier
[1989] hi def link ngxVariableString PreProc
[1990] hi def link ngxString String
[1991] hi def link ngxListenString String
[1992] 
[1993] hi def link ngxBoolean Boolean
[1994] hi def link ngxDirectiveBlock Statement
[1995] hi def link ngxDirectiveImportant Type
[1996] hi def link ngxDirectiveListen Type
[1997] hi def link ngxDirectiveControl Keyword
[1998] hi def link ngxDirectiveError Constant
[1999] hi def link ngxDirectiveDeprecated Error
[2000] hi def link ngxDirective Identifier
[2001] hi def link ngxDirectiveThirdParty Special
[2002] hi def link ngxDirectiveThirdPartyDeprecated Error
[2003] 
[2004] hi def link ngxListenOptions Keyword
[2005] hi def link ngxListenOptionsDeprecated Error
[2006] 
[2007] let &cpo = s:save_cpo
[2008] unlet s:save_cpo
[2009] 
[2010] let b:current_syntax = "nginx"
