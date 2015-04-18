/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2015 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Sascha Schumann <sascha@schumann.cx>                        |
   |          Gerrit Venema <php@golgol.nl>
   |          Parts based on Apache 1.3 SAPI module by                    |
   |          Rasmus Lerdorf and Zeev Suraski                             |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#define ZEND_INCLUDE_FULL_WINDOWS_HEADERS

#include "php.h"
#include "php_main.h"
#include "php_ini.h"
#include "php_variables.h"
#include "SAPI.h"

#include <fcntl.h>

#include "ext/standard/php_smart_str.h"
#ifndef NETWARE
#include "ext/standard/php_standard.h"
#else
#include "ext/standard/basic_functions.h"
#endif

#include "apr_strings.h"
#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"
#include "ap_mpm.h"

#include "php_apache.h"

#ifdef PHP_WIN32
# if _MSC_VER <= 1300
#  include "win32/php_strtoi64.h"
# endif
#endif

/* UnixWare and Netware define shutdown to _shutdown, which causes problems later
 * on when using a structure member named shutdown. Since this source
 * file does not use the system call shutdown, it is safe to #undef it.K
 */
#undef shutdown

#define PHP_MAGIC_TYPE "application/x-httpd-php"
#define PHP_SOURCE_MAGIC_TYPE "application/x-httpd-php-source"
#define PHP_SCRIPT "php5-script"

/* A way to specify the location of the php.ini dir in an apache directive */
char *apache2_php_ini_path_override = NULL;

static int
php_apache_sapi_ub_write(const char *str, uint str_length TSRMLS_DC)
{
	request_rec *r;
	php_struct *ctx;

	ctx = SG(server_context);
	r = ctx->r;

	if (ap_rwrite(str, str_length, r) < 0) {
		php_handle_aborted_connection();
	}

	return str_length; /* we always consume all the data passed to us. */
}

static int
php_apache_sapi_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers TSRMLS_DC)
{
	php_struct *ctx;
	char *val, *ptr;

	ctx = SG(server_context);

	switch (op) {
		case SAPI_HEADER_DELETE:
			apr_table_unset(ctx->r->headers_out, sapi_header->header);
			return 0;

		case SAPI_HEADER_DELETE_ALL:
			apr_table_clear(ctx->r->headers_out);
			return 0;

		case SAPI_HEADER_ADD:
		case SAPI_HEADER_REPLACE:
			val = strchr(sapi_header->header, ':');

			if (!val) {
				return 0;
			}
			ptr = val;

			*val = '\0';

			do {
				val++;
			} while (*val == ' ');

			if (!strcasecmp(sapi_header->header, "content-type")) {
				if (ctx->content_type) {
					efree(ctx->content_type);
				}
				ctx->content_type = estrdup(val);
			} else if (!strcasecmp(sapi_header->header, "content-length")) {
#ifdef PHP_WIN32
# ifdef APR_HAS_LARGE_FILES
				ap_set_content_length(ctx->r, (apr_off_t) _strtoui64(val, (char **)NULL, 10));
# else
				ap_set_content_length(ctx->r, (apr_off_t) strtol(val, (char **)NULL, 10));
# endif
#else
				ap_set_content_length(ctx->r, (apr_off_t) strtol(val, (char **)NULL, 10));
#endif
			} else if (op == SAPI_HEADER_REPLACE) {
				apr_table_set(ctx->r->headers_out, sapi_header->header, val);
			} else {
				apr_table_add(ctx->r->headers_out, sapi_header->header, val);
			}

			*ptr = ':';

			return SAPI_HEADER_ADD;

		default:
			return 0;
	}
}

static int
php_apache_sapi_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
	php_struct *ctx = SG(server_context);
	const char *sline = SG(sapi_headers).http_status_line;

	ctx->r->status = SG(sapi_headers).http_response_code;

	/* httpd requires that r->status_line is set to the first digit of
	 * the status-code: */
	if (sline && strlen(sline) > 12 && strncmp(sline, "HTTP/1.", 7) == 0 && sline[8] == ' ') {
		ctx->r->status_line = apr_pstrdup(ctx->r->pool, sline + 9);
		ctx->r->proto_num = 1000 + (sline[7]-'0');
		if ((sline[7]-'0') == 0) {
			apr_table_set(ctx->r->subprocess_env, "force-response-1.0", "true");
		}
	}

	/*	call ap_set_content_type only once, else each time we call it,
		configured output filters for that content type will be added */
	if (!ctx->content_type) {
		ctx->content_type = sapi_get_default_content_type(TSRMLS_C);
	}
	ap_set_content_type(ctx->r, apr_pstrdup(ctx->r->pool, ctx->content_type));
	efree(ctx->content_type);
	ctx->content_type = NULL;

	return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static int
php_apache_sapi_read_post(char *buf, uint count_bytes TSRMLS_DC)
{
	/*
	 * This routine will be called:
	 * On PHP request_startup in php_hash_environment IF request method is POST,
	 *  AND P is included in GPC setting.
	 * On PHP request shutdown during sapi_deactivate PHP will always read remaining bytes.
	 * But ALSO on any reading of php://stdin during script execution.
	 */

	int tlen;
	php_struct *ctx = SG(server_context);
	request_rec *r;
	apr_size_t len_asked;

	r = ctx->r;
	tlen = (int)count_bytes;
	if (tlen < 0) {
		// count_bytes is overflowing int
		r->status = HTTP_INTERNAL_SERVER_ERROR;
		return 0;
	}

	tlen = 0;
	len_asked = (apr_size_t)count_bytes;

	if (r->status == HTTP_REQUEST_ENTITY_TOO_LARGE || r->status == HTTP_INTERNAL_SERVER_ERROR) {
		/*
		 * We are acting as a 413 ErrorDocument
		 * OR there was a bailout and this is shutdown.
		 * Avoid reading any data from input either way.
		 */
		return 0;
	}

	if (ctx->kept_body && (ctx->flags & PHP_CTX_BODY_IN_STORE)) {
		/*
		 * Satisfy request from stored buffer
		 */
		apr_bucket_brigade *bb;
		apr_bucket_brigade *brigade;
		apr_off_t lenb;
		apr_status_t rv;
		apr_size_t len_gotten;
		apr_bucket *after;
		apr_bucket *bucket_in;
		if (ctx->flags & PHP_CTX_BODY_EOS) {
			// The body has been exhausted already
			return 0;
		}
		brigade = ctx->kept_body;
		rv = apr_brigade_length(brigade, 1, &lenb);
		if (rv != APR_SUCCESS) {
			r->status = HTTP_INTERNAL_SERVER_ERROR;
			return 0;
		}
		if (lenb > len_asked) {
			len_gotten = len_asked;
			rv = apr_brigade_partition(brigade, len_asked, &after);
			if (rv != APR_SUCCESS) {
				r->status = HTTP_INTERNAL_SERVER_ERROR;
				return 0;
			}
		} else {
			len_gotten = lenb;
			after = APR_BRIGADE_LAST(brigade);
			ctx->flags |= PHP_CTX_BODY_EOS;
		}
		bb = apr_brigade_split(brigade, after);
		ctx->kept_body = bb;
		apr_brigade_flatten(brigade, buf, &len_gotten);
		apr_brigade_destroy(brigade);
		tlen = len_gotten;
	} else {
		/*
		 * There is no stored body data available. Read data from the input filter stack.
		 * During read from input filters we can hit a filter that fires an internal redirect.
		 * For example body size limit.
		 */
		int eos_reached = 0;
		apr_off_t len;
		apr_size_t len_gotten;
		apr_status_t rv;
		apr_bucket_brigade *brigade;
		apr_bucket *bucket_in, *bucket_sentinel;
		brigade = ctx->brigade;
		len = len_asked;
		if (ctx->flags & PHP_CTX_BODY_EOS) {
			// The body has been exhausted already
			return 0;
		}
		while (1) {
			rv = ap_get_brigade(r->input_filters, brigade, AP_MODE_READBYTES, APR_BLOCK_READ, len);
			if (rv != APR_SUCCESS && rv != APR_EAGAIN && rv != APR_EOF) {
				break;
			} else {
				// Normalize the return value
				rv = APR_SUCCESS;
			}
			// See if there is an end of stream in here
			bucket_sentinel = APR_BRIGADE_SENTINEL(brigade);
			for (bucket_in = APR_BRIGADE_FIRST(brigade);
				bucket_in != bucket_sentinel;
				bucket_in = APR_BUCKET_NEXT(bucket_in))
			{
				if (APR_BUCKET_IS_EOS(bucket_in)) {
					eos_reached = 1;
					break;
				}
			}
			// What length of data did we get?
			rv = apr_brigade_length(brigade, 1, &len);
			if (rv != APR_SUCCESS) {
				break;
			}
			tlen += (int) len;
			len_gotten = (apr_size_t) len;
			if (len_gotten) {
				// Put the data in the buffer
				apr_brigade_flatten(brigade, buf, &len_gotten);
				buf += len_gotten;
			}
			// See if we got the lot or are at the end of stream.
			if (tlen == len_asked || eos_reached) {
				break;
			}
			len = len_asked - tlen;
			apr_brigade_cleanup(brigade);
		}
		apr_brigade_cleanup(brigade);
		if (rv != APR_SUCCESS) {
			r->status = HTTP_INTERNAL_SERVER_ERROR;
			if (EG(bailout)) {
				zend_bailout();
			}
			return 0;
		}
		if (eos_reached) {
			ctx->flags |= PHP_CTX_BODY_EOS;
		}
	}
	return tlen;
}

static struct stat*
php_apache_sapi_get_stat(TSRMLS_D)
{
	php_struct *ctx = SG(server_context);

	ctx->finfo.st_uid = ctx->r->finfo.user;
	ctx->finfo.st_gid = ctx->r->finfo.group;
	ctx->finfo.st_dev = ctx->r->finfo.device;
	ctx->finfo.st_ino = ctx->r->finfo.inode;
#if defined(NETWARE) && defined(CLIB_STAT_PATCH)
	ctx->finfo.st_atime.tv_sec = apr_time_sec(ctx->r->finfo.atime);
	ctx->finfo.st_mtime.tv_sec = apr_time_sec(ctx->r->finfo.mtime);
	ctx->finfo.st_ctime.tv_sec = apr_time_sec(ctx->r->finfo.ctime);
#else
	ctx->finfo.st_atime = apr_time_sec(ctx->r->finfo.atime);
	ctx->finfo.st_mtime = apr_time_sec(ctx->r->finfo.mtime);
	ctx->finfo.st_ctime = apr_time_sec(ctx->r->finfo.ctime);
#endif

	ctx->finfo.st_size = ctx->r->finfo.size;
	ctx->finfo.st_nlink = ctx->r->finfo.nlink;

	return &ctx->finfo;
}

static char *
php_apache_sapi_read_cookies(TSRMLS_D)
{
	php_struct *ctx = SG(server_context);
	const char *http_cookie;

	http_cookie = apr_table_get(ctx->r->headers_in, "cookie");

	/* The SAPI interface should use 'const char *' */
	return (char *) http_cookie;
}

static char *
php_apache_sapi_getenv(char *name, size_t name_len TSRMLS_DC)
{
	php_struct *ctx = SG(server_context);
	const char *env_var;

	if (ctx == NULL) {
		return NULL;
	}

	env_var = apr_table_get(ctx->r->subprocess_env, name);

	return (char *) env_var;
}

static void
php_apache_sapi_register_variables(zval *track_vars_array TSRMLS_DC)
{
	php_struct *ctx = SG(server_context);
	const apr_array_header_t *arr = apr_table_elts(ctx->r->subprocess_env);
	char *key, *val;
	int new_val_len;

	APR_ARRAY_FOREACH_OPEN(arr, key, val)
		if (!val) {
			val = "";
		}
		if (sapi_module.input_filter(PARSE_SERVER, key, &val, strlen(val), (unsigned int *)&new_val_len TSRMLS_CC)) {
			php_register_variable_safe(key, val, new_val_len, track_vars_array TSRMLS_CC);
		}
	APR_ARRAY_FOREACH_CLOSE()

	if (sapi_module.input_filter(PARSE_SERVER, "PHP_SELF", &ctx->r->uri, strlen(ctx->r->uri), (unsigned int *)&new_val_len TSRMLS_CC)) {
		php_register_variable_safe("PHP_SELF", ctx->r->uri, new_val_len, track_vars_array TSRMLS_CC);
	}
}

static void
php_apache_sapi_flush(void *server_context)
{
	php_struct *ctx;
	request_rec *r;
	TSRMLS_FETCH();

	ctx = server_context;

	/* If we haven't registered a server_context yet,
	 * then don't bother flushing. */
	if (!server_context) {
		return;
	}

	r = ctx->r;

	sapi_send_headers(TSRMLS_C);

	r->status = SG(sapi_headers).http_response_code;
	SG(headers_sent) = 1;

	if (ap_rflush(r) < 0 || r->connection->aborted) {
		php_handle_aborted_connection();
	}
}

static void php_apache_sapi_log_message(char *msg TSRMLS_DC)
{
	php_struct *ctx;

	ctx = SG(server_context);

	if (ctx == NULL) { /* we haven't initialized our ctx yet, oh well */
		ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, 0, NULL, "%s", msg);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, "%s", msg);
	}
}

static void php_apache_sapi_log_message_ex(char *msg, request_rec *r TSRMLS_DC)
{
	if (r) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, msg, r->filename);
	} else {
		php_apache_sapi_log_message(msg TSRMLS_CC);
	}
}

static double php_apache_sapi_get_request_time(TSRMLS_D)
{
	php_struct *ctx = SG(server_context);
	return ((double) apr_time_as_msec(ctx->r->request_time)) / 1000.0;
}

extern zend_module_entry php_apache_module;

static int php_apache2_startup(sapi_module_struct *sapi_module)
{
	if (php_module_startup(sapi_module, &php_apache_module, 1)==FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}

static sapi_module_struct apache2_sapi_module = {
	"apache2handler",
	"Apache 2.0 Handler",

	php_apache2_startup,				/* startup */
	php_module_shutdown_wrapper,			/* shutdown */

	NULL,						/* activate */
	NULL,						/* deactivate */

	php_apache_sapi_ub_write,			/* unbuffered write */
	php_apache_sapi_flush,				/* flush */
	php_apache_sapi_get_stat,			/* get uid */
	php_apache_sapi_getenv,				/* getenv */

	php_error,					/* error handler */

	php_apache_sapi_header_handler,			/* header handler */
	php_apache_sapi_send_headers,			/* send headers handler */
	NULL,						/* send header handler */

	php_apache_sapi_read_post,			/* read POST data */
	php_apache_sapi_read_cookies,			/* read Cookies */

	php_apache_sapi_register_variables,
	php_apache_sapi_log_message,			/* Log message */
	php_apache_sapi_get_request_time,		/* Request Time */
	NULL,						/* Child Terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};

static apr_status_t php_apache_server_shutdown(void *tmp)
{
	apache2_sapi_module.shutdown(&apache2_sapi_module);
	sapi_shutdown();
#ifdef ZTS
	tsrm_shutdown();
#endif
	return APR_SUCCESS;
}

static apr_status_t php_apache_child_shutdown(void *tmp)
{
	apache2_sapi_module.shutdown(&apache2_sapi_module);
#if defined(ZTS) && !defined(PHP_WIN32)
	tsrm_shutdown();
#endif
	return APR_SUCCESS;
}

static void php_apache_add_version(apr_pool_t *p)
{
	TSRMLS_FETCH();
	if (PG(expose_php)) {
		ap_add_version_component(p, "PHP/" PHP_VERSION);
	}
}

static int php_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
#ifndef ZTS
	int threaded_mpm;

	ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
	if(threaded_mpm) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Apache is running a threaded MPM, but your PHP Module is not compiled to be threadsafe.  You need to recompile PHP.");
		return DONE;
	}
#endif
	/* When this is NULL, apache won't override the hard-coded default
	 * php.ini path setting. */
	apache2_php_ini_path_override = NULL;
	return OK;
}

static int
php_apache_server_startup(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	void *data = NULL;
	const char *userdata_key = "apache2hook_post_config";

	/* Apache will load, unload and then reload a DSO module. This
	 * prevents us from starting PHP until the second load. */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		/* We must use set() here and *not* setn(), otherwise the
		 * static string pointed to by userdata_key will be mapped
		 * to a different location when the DSO is reloaded and the
		 * pointers won't match, causing get() to return NULL when
		 * we expected it to return non-NULL. */
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	/* Set up our overridden path. */
	if (apache2_php_ini_path_override) {
		apache2_sapi_module.php_ini_path_override = apache2_php_ini_path_override;
	}
#ifdef ZTS
	tsrm_startup(1, 1, 0, NULL);
#endif
	sapi_startup(&apache2_sapi_module);
	apache2_sapi_module.startup(&apache2_sapi_module);
	apr_pool_cleanup_register(pconf, NULL, php_apache_server_shutdown, apr_pool_cleanup_null);
	php_apache_add_version(pconf);

	return OK;
}

static int php_apache_request_ctor(request_rec *r, php_struct *ctx TSRMLS_DC)
{
	char *content_length;
	const char *auth;

	SG(sapi_headers).http_response_code = !r->status ? HTTP_OK : r->status;
	SG(request_info).content_type = apr_table_get(r->headers_in, "Content-Type");
	SG(request_info).query_string = apr_pstrdup(r->pool, r->args);
	SG(request_info).request_method = r->method;
	SG(request_info).proto_num = r->proto_num;
	SG(request_info).request_uri = apr_pstrdup(r->pool, r->uri);
	SG(request_info).path_translated = apr_pstrdup(r->pool, r->filename);
	r->no_local_copy = 1;

	content_length = (char *) apr_table_get(r->headers_in, "Content-Length");
	SG(request_info).content_length = (content_length ? atol(content_length) : 0);

	apr_table_unset(r->headers_out, "Content-Length");
	apr_table_unset(r->headers_out, "Last-Modified");
	apr_table_unset(r->headers_out, "Expires");
	apr_table_unset(r->headers_out, "ETag");

	auth = apr_table_get(r->headers_in, "Authorization");
	php_handle_auth_data(auth TSRMLS_CC);

	if (SG(request_info).auth_user == NULL && r->user) {
		SG(request_info).auth_user = estrdup(r->user);
	}

	ctx->r->user = apr_pstrdup(ctx->r->pool, SG(request_info).auth_user);

	return php_request_startup(TSRMLS_C);
}

static void php_apache_request_dtor(request_rec *r TSRMLS_DC)
{
	/*
	 * After dtor the state of CG and possibly others is NOT the same as before ctor.
	 * This means that the very first request to the PHP engine does NOT encounter the
	 * same PHP situation as follow-on requests.
	 * This has been observed to make a difference to the Upload Progress function in ext/session
	 */
	php_request_shutdown(NULL);
}

static void php_apache_ini_dtor(request_rec *r, request_rec *p TSRMLS_DC)
{
	if (strcmp(r->protocol, "INCLUDED")) {
		zend_try { zend_ini_deactivate(TSRMLS_C); } zend_end_try();
	} else {
typedef struct {
	HashTable config;
} php_conf_rec;
		char *str;
		uint str_len;
		php_conf_rec *c = ap_get_module_config(r->per_dir_config, &php5_module);

		for (zend_hash_internal_pointer_reset(&c->config);
			zend_hash_get_current_key_ex(&c->config, &str, &str_len, NULL, 0,  NULL) == HASH_KEY_IS_STRING;
			zend_hash_move_forward(&c->config)
		) {
			zend_restore_ini_entry(str, str_len, ZEND_INI_STAGE_SHUTDOWN);
		}
	}
	if (p) {
		((php_struct *)SG(server_context))->r = p;
		((php_struct *)SG(server_context))->nesting_level--;
	} else {
		SG(server_context) = NULL;
	}
}

static int php_handler(request_rec *r)
{
	php_struct *ctx;
	void *conf;
	request_rec * parent_req = NULL;
	if (r->finfo.filetype == APR_NOFILE) {
		// Save time on redirect handler requests
		return DECLINED;
	}
	TSRMLS_FETCH();

#define PHPAP_INI_OFF php_apache_ini_dtor(r, parent_req TSRMLS_CC);

	ctx = SG(server_context);

	if (ctx == NULL) {
		ctx = SG(server_context) = apr_pcalloc(r->pool, sizeof(*ctx));
		/*
		 * This allocation will happen at first access of the handler in a client request
		 * It may be a PHP script set for ErrorDocument, and not called explicitly
		 * by the client request. Or it may not be PHP and get DECLINED later on.
		 * Setup the context just in case it will be needed.
		 */
	}

	/* apply_config() needs r in some cases, so allocate server_context early */
	if (ctx->flags & PHP_CTX_CONSTRUCTED) {
		/* This is a subrequest of a PHP request tree.
		 * The direct parent of this subrequest does not have to be a PHP request.
		 * The pointer called parent is merely the first PHP script walking up the request tree.
		 */
		parent_req = ctx->r;
		ctx->nesting_level++;
	}

	ctx->r = r;
	conf = ap_get_module_config(r->per_dir_config, &php5_module);
	apply_config(conf);

	/* At this point there is a context allocated but it is not sure IF we are really going to handle this call with PHP.
	 * The following section runs through some cases where we will NOT. 
	 * IF not, then we roll back the changes to context and config and return the reason. */

	if (strcmp(r->handler, PHP_MAGIC_TYPE) && strcmp(r->handler, PHP_SOURCE_MAGIC_TYPE) && strcmp(r->handler, PHP_SCRIPT)) {
		/* Check for xbithack in this case. */
		if (!AP2(xbithack) || strcmp(r->handler, "text/html") || !(r->finfo.protection & APR_UEXECUTE)) {
			PHPAP_INI_OFF;
			return DECLINED;
		}
	}

	/* Give a 404 if PATH_INFO is used but is explicitly disabled in
	 * the configuration; default behaviour is to accept. */
	if (r->used_path_info == AP_REQ_REJECT_PATH_INFO
		&& r->path_info && r->path_info[0]) {
		PHPAP_INI_OFF;
		return HTTP_NOT_FOUND;
	}

	/* handle situations where user turns the engine off */
	if (!AP2(engine)) {
		PHPAP_INI_OFF;
		return DECLINED;
	}

	if (r->finfo.filetype == 0) {
		php_apache_sapi_log_message_ex("script '%s' not found or unable to stat", r TSRMLS_CC);
		PHPAP_INI_OFF;
		return HTTP_NOT_FOUND;
	}
	if (r->finfo.filetype == APR_DIR) {
		php_apache_sapi_log_message_ex("attempt to invoke directory '%s' as script", r TSRMLS_CC);
		PHPAP_INI_OFF;
		return HTTP_FORBIDDEN;
	}	
	/* End of section testing for cases we will NOT handle */


	/*
	 * Body limit checks for all methods
	 * Only for main request, and if not incoming ErrorDocument, and not tested already.
	 */
	if (!parent_req && r->status == HTTP_OK && !(ctx->flags & PHP_CTX_BODYLIMIT_TESTED)) {
		apr_off_t limit;
		apr_off_t limit_ap;
		limit_ap = ap_get_limit_req_body(r);
		if (limit_ap == 0)  {
			/*
			 * There is no limit it seems...
			 * Possible gotcha's:
			 * mod_request, kept body for Apache >=2.4 can put in a limit
			 * In chunked transfer, each chunk header/footer must stay below a request_line_limit
			 * custom filters...
			 */
			limit = 0;
		} else {
			limit = limit_ap;
		}
		if (limit) {
			/*
			 * Make the handler return a 413 BEFORE executing PHP script.
			 * Read up to the limit bytes to make sure the body is smaller.
			 * In a chunked body Apache counts part of the chunking overhead for LimitRequestBody.
			 * The bytes read here will be stored for reading later.
			 */
			int eos_reached = 0;
			apr_off_t len, len_read;
			apr_status_t rv_get, rv_copy, rv_length;
			apr_bucket_brigade *brigade;
			apr_bucket_brigade *brigade_kept_body;
			apr_bucket *bucket_in, *bucket_keep, *bucket_sentinel;

			// Create a brigade for the body
			brigade_kept_body = apr_brigade_create(r->pool, r->connection->bucket_alloc);
			// Try for one more than the limit
			limit++;
			for (len = 0;len < limit;) {
				len_read = limit - len;
				brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
				rv_get = ap_get_brigade(r->input_filters, brigade, AP_MODE_READBYTES, APR_BLOCK_READ, len_read);
				/*
				 * EAGAIN can happen with overly long chunk extensions or bogus data after the chunk.
				 * Should not happen with Content-Length bodies.
				 * APR_EOF means a content body was cut short but last data may have been returned.
				 */ 
				if (rv_get == APR_EOF || rv_get == APR_EAGAIN) {
					// Normalize
					rv_get = APR_SUCCESS;
				}
				if (rv_get != APR_SUCCESS) {
					// Bail
					break;
				}
				rv_length = apr_brigade_length(brigade, 1, &len_read);
				if (rv_length != APR_SUCCESS) {
					// Bail
					break;
				}
				len += len_read;
				// Copy the buckets
				// TODO filter out unwanted metadata buckets
				bucket_sentinel = APR_BRIGADE_SENTINEL(brigade);
				for (bucket_in = APR_BRIGADE_FIRST(brigade);
					bucket_in != bucket_sentinel;
					bucket_in = APR_BUCKET_NEXT(bucket_in))
				{
					rv_copy = apr_bucket_copy(bucket_in, &bucket_keep);
					if (rv_copy == APR_SUCCESS) {
						APR_BRIGADE_INSERT_TAIL(brigade_kept_body, bucket_keep);
						if (APR_BUCKET_IS_EOS(bucket_in)) {
							eos_reached = 1;
							break;
						}
					} else {
						break;
					}
				}
				// Reset the brigade for ap_get_brigade
				apr_brigade_cleanup(brigade);
				if (eos_reached) {
					break;
				}
				if (rv_copy != APR_SUCCESS) {
					break;
				}
			}
			apr_brigade_destroy(brigade);
			if (rv_get != APR_SUCCESS || rv_length != APR_SUCCESS || rv_copy != APR_SUCCESS)
			{
				php_apache_sapi_log_message_ex("An error occurred while reading the request body.", r TSRMLS_CC);
				if (r->status != HTTP_OK) {
				} else if (rv_get != APR_SUCCESS) {
					r->status = HTTP_BAD_REQUEST;
				} else {
					r->status = HTTP_INTERNAL_SERVER_ERROR;
				}
				return DONE;
			}
			if (r->status != HTTP_OK) {
				/*
				 * We crossed the limit of some input filter
				 * A 413 will have generated its ErrorDocument
				 * There is a possibility we triggered a 413
				 * that PHP wouldn't have triggered in startup.
				 * But it would have done so in shutdown.
				 */
				php_apache_sapi_log_message_ex("An Apache limit was hit during a read of the request body. Shutting down the request before PHP execution.", r TSRMLS_CC);
				return DONE;
			}
			/*
			 * Reading up to the limit went well.
			 * PHP probably won't hit a 413 while reading.
			 * The body length stays under the Apache limit.
			 * AND no chunks exceeded the limit request line.
			 * It is stored for later reading by PHP.
			 */
			apr_bucket *bucket;
			if (!eos_reached) {
				// Make sure there is an EOS bucket at the end
				bucket = APR_BRIGADE_LAST(brigade_kept_body);
				if (!APR_BUCKET_IS_EOS(bucket)) {
					bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
					APR_BRIGADE_INSERT_TAIL(brigade_kept_body, bucket);
				}
			}
			ctx->kept_body = brigade_kept_body;
			ctx->flags |= PHP_CTX_BODY_IN_STORE;
		}
		ctx->flags |= PHP_CTX_BODYLIMIT_TESTED;
	}

	/* Setup the CGI variables if this is the main request */
	if (r->main == NULL ||
		/* .. or if the sub-request environment differs from the main-request. */
		r->subprocess_env != r->main->subprocess_env
	) {
		/* setup standard CGI variables */
		ap_add_common_vars(r);
		ap_add_cgi_vars(r);
	}

	// ~~~Start of hardening section

	/*
	 * Hardening against unresolved reentry cases.
	 * To execute a PHP subrequest, the SAPI must ALWAYS be fully activated.
	 */
	if (ctx->flags & PHP_CTX_CONSTRUCTED) {
		if (!SG(sapi_started) || !EG(active)) {
			php_apache_sapi_log_message_ex("A PHP subrequest came in during PHP startup or shutdown. It can not be handled in this state.", r TSRMLS_CC);
			r->status = HTTP_INTERNAL_SERVER_ERROR;
			return DONE;
		}
		if (r->status == HTTP_REQUEST_ENTITY_TOO_LARGE) {
			/*
			 * We hit an input filter limit with a PHP context already constructed.
			 *
			 * While reading a request body, Apache can fire filter actions.
			 * One of those actions is checking for a body limit and calling ErrorDocument
			 * An ErrorDocument can be set to a PHP script, thus arriving in this clause.
			 *
			 * In this state unfortunately we cannot safely execute PHP.
			 * Let Apache return a status 413.
			 */
			php_apache_sapi_log_message_ex("An Apache input limit was hit during a PHP read and a PHP ErrorDocument was also set, which will not be allowed to run as a subdocument.", r TSRMLS_CC);
			return DONE;
		}
		// Continue with subrequest in running PHP context.
	}

	// ~~~End of hardening section

	/* NOTE
	 * The bailout strategy of zend_try for runtime errors is not foolproof in this handler.
	 * IF input is read from input filters during execution of a subrequest AND a bailout occurs,
	 * ths state of the input becomes undefined and Apache reads of input may loop infinitely,
	 * at least with chunked body inputs where the length is not fixed beforehand.
	 * We will try to avoid reading input and drop the connection as soon as possible.
	 */

	if (!parent_req) {
		// Make this the first try, so we can bubble up later.
		EG(bailout) = NULL;
	}

zend_try {

	if ((ctx->flags & PHP_CTX_CONSTRUCTED) == 0) {
		ctx->brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
		// Coming in WITHOUT an active context. The SAPI must be activated to handle PHP.
		apr_status_t status_before = r->status;
		if (php_apache_request_ctor(r, ctx TSRMLS_CC)!=SUCCESS) {
			zend_bailout();
			/* lands after next zend_end_try */
		}
		ctx->flags |= PHP_CTX_CONSTRUCTED;
		// A subrequest during construction may have set an Error.
		if (r->status != status_before && r->status != HTTP_OK) {
			php_apache_sapi_log_message_ex("An Apache filter threw an error during PHP setup. LimitRequestBody or KeptBodySize exceeded?", r TSRMLS_CC);
			zend_bailout();
		}
	}

	if (AP2(last_modified)) {
		ap_update_mtime(r, r->finfo.mtime);
		ap_set_last_modified(r);
	}

	/* Determine if we need to parse the file or show the source */
	if (strncmp(r->handler, PHP_SOURCE_MAGIC_TYPE, sizeof(PHP_SOURCE_MAGIC_TYPE) - 1) == 0) {
		zend_syntax_highlighter_ini syntax_highlighter_ini;
		php_get_highlight_struct(&syntax_highlighter_ini);
		highlight_file((char *)r->filename, &syntax_highlighter_ini TSRMLS_CC);
	} else {
		zend_file_handle zfd;

		zfd.type = ZEND_HANDLE_FILENAME;
		zfd.filename = (char *) r->filename;
		zfd.free_filename = 0;
		zfd.opened_path = NULL;

		ctx->flags |= PHP_CTX_SCRIPT_RUNNING;
		if (!parent_req) {
			php_execute_script(&zfd TSRMLS_CC);
		} else {
			zend_execute_scripts(ZEND_INCLUDE TSRMLS_CC, NULL, 1, &zfd);
		}
		ctx->flags &= ~PHP_CTX_SCRIPT_RUNNING;

		apr_table_set(r->notes, "mod_php_memory_usage",
			apr_psprintf(ctx->r->pool, "%" APR_SIZE_T_FMT, zend_memory_peak_usage(1 TSRMLS_CC)));
	}

} zend_end_try();
	/* zend_bailout will land here */
	if (CG(unclean_shutdown)) {
		/*
		 * Only handle the exit in the main PHP script.
		 * Otherwise PHP script may be hit along the way
		 * with a PHP engine that is partly shutdown.
		 */
		if (EG(bailout)) {
			// TRQ Jump up the stack one level
			ctx->nesting_level--;
			LONGJMP(*EG(bailout), FAILURE);
		}
		/*
		 * Now back at the main script, proceed to exit.
		 * Unclean shutdown also happens with the "die" instruction.
		 * Avoid reading from input filters after lngjmps so drop connection.
		 */
		ctx->flags &= ~PHP_CTX_SCRIPT_RUNNING;
		r->connection->keepalive = AP_CONN_CLOSE;
	}

	if (!parent_req) {
		/*
		 * A PHP tree of requests with possible subrequests has been completely handled.
		 * More PHP requests may come from this client request if the root handler is not PHP.
		 * The SAPI will have to be activated again for them.
		 */
		php_apache_request_dtor(r TSRMLS_CC);
		SG(server_context) = NULL;
		if (ctx->kept_body) {
			apr_brigade_cleanup(ctx->kept_body);
		}
		if (ctx->brigade) {
			apr_brigade_cleanup(ctx->brigade);
		}
		ctx = NULL;
	} else {
		ctx->r = parent_req;
		ctx->nesting_level--;
		return OK;
	}

	apr_bucket_brigade *brigade;
	apr_bucket *bucket;
	apr_status_t rv;
	brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(brigade, bucket);
	rv = ap_pass_brigade(r->output_filters, brigade);
	apr_brigade_cleanup(brigade);
	if (rv == APR_SUCCESS || r->status != HTTP_OK || r->connection->aborted) {
	    return OK;
	} else {
		php_apache_sapi_log_message_ex("An error occurred in Apache on closing of PHP script output.", r TSRMLS_CC);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
}

static void php_apache_child_init(apr_pool_t *pchild, server_rec *s)
{
	apr_pool_cleanup_register(pchild, NULL, php_apache_child_shutdown, apr_pool_cleanup_null);
}

void php_ap2_register_hook(apr_pool_t *p)
{
	ap_hook_pre_config(php_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(php_apache_server_startup, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(php_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(php_apache_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
