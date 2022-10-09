/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * http_auth_plain: plaintext authentication
 *
 * Based on http_auth
 * Adapted by Piotr Roszatycki <dexter@debian.org>
 * 
 * Original code:
 * 
 * Rob McCool
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower
 *         modules if and only if the userid is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_main.h"

#include "mod_auth.h"


#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_plain);
#endif

typedef struct {
    char *auth_pwfile;
    char *auth_grpfile;
    int auth_authoritative;
} auth_plain_config_rec;

static void *create_auth_plain_dir_config(apr_pool_t *p, char *d)
{
    auth_plain_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->auth_pwfile = NULL;     /* just to illustrate the default really */
    conf->auth_grpfile = NULL;    /* unless you have a broken HP cc */
    conf->auth_authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const char *ap_set_file_slot_curdir(cmd_parms *cmd, void *struct_ptr,
                                           const char *arg,
                                           /* for compatibility */
                                           const char *unused_arg2)
{
    /* Prepend current directory to relative arg. */
    const char *path;
    int offset = (int)(long)cmd->info;

    if (ap_os_is_path_absolute(cmd->pool, arg)) {
        path = arg;
    } else {
        path = ap_make_full_path(cmd->pool, cmd->path ? cmd->path : ap_server_root, arg);
    }

    if (!path) {
        return apr_pstrcat(cmd->pool, "Invalid file path ",
                           arg, NULL);
    }

    *(const char **) ((char*)struct_ptr + offset) = path;

    return NULL;
}

static const command_rec auth_plain_cmds[] =
{
    AP_INIT_TAKE12("AuthPlainUserFile", ap_set_file_slot_curdir,
                   (void *)APR_OFFSETOF(auth_plain_config_rec, auth_pwfile),
                   OR_AUTHCFG, "text file containing user IDs and passwords"),
    AP_INIT_TAKE12("AuthPlainGroupFile", ap_set_file_slot_curdir,
                   (void *)APR_OFFSETOF(auth_plain_config_rec, auth_grpfile),
                   OR_AUTHCFG,
                   "text file containing group names and member user IDs"),
    AP_INIT_FLAG("AuthPlainAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(auth_plain_config_rec, auth_authoritative),
                 OR_AUTHCFG,
                 "Set to 'no' to allow access control to be passed along to "
                 "lower modules if the UserID is not known to this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_plain_module;

static char *get_plain_pw(request_rec *r, char *user, char *auth_pwfile)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *rpw, *w;
    apr_status_t status;

    if ((status = ap_pcfg_openfile(&f, r->pool, auth_pwfile)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Could not open password file: %s", auth_pwfile);
        return NULL;
    }
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');

        if (!strcmp(user, w)) {
            ap_cfg_closefile(f);
            return ap_getword(r->pool, &rpw, ':');
        }
    }
    ap_cfg_closefile(f);
    return NULL;
}

static apr_table_t *plain_groups_for_user(apr_pool_t *p, char *user, char *grpfile)
{
    ap_configfile_t *f;
    apr_table_t *grps = apr_table_make(p, 15);
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;
    apr_status_t status;

    if ((status = ap_pcfg_openfile(&f, p, grpfile)) != APR_SUCCESS) {
/*add?  aplog_error(APLOG_MARK, APLOG_ERR, NULL,
                    "Could not open group file: %s", grpfile);*/
        return NULL;
    }

    apr_pool_create(&sp, p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        ll = l;
        apr_pool_clear(sp);

        group_name = ap_getword(sp, &ll, ':');

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
            if (!strcmp(w, user)) {
                apr_table_setn(grps, apr_pstrdup(p, group_name), "in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);
    return grps;
}

/* These functions return AUTH_GRANTED if client is OK, and proper error
 * status if not... either AUTH_DENIED, if we made a check, and it failed,
 * or AUTH_GENERAL_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */

static authn_status check_plain_pw(request_rec *r, const char *user,
                                   const char *password)
{
    auth_plain_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                 &auth_plain_module);
    char *real_pw;

    if (!conf->auth_pwfile) {
        return DECLINED;
    }

    if (!(real_pw = get_plain_pw(r, r->user, conf->auth_pwfile))) {
        if (!(conf->auth_authoritative)) {
            return DECLINED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s not found: %s", r->user, r->uri);
        ap_note_basic_auth_failure(r);
        return AUTH_DENIED;
    }
    if (strcmp(password, real_pw) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s: authentication failure for \"%s\": "
                      "Plain Password Mismatch",
                      r->user, r->uri);
        ap_note_basic_auth_failure(r);
        return AUTH_DENIED;
    }
    return AUTH_GRANTED;
}

/* Checking ID */

static authz_status user_check_authorization(request_rec *r,
                                             const char *require_args,
                                             const void *parsed_require_args)
{
    const char *t, *w;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (!strcmp(r->user, w)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: user %s not allowed access",
                  r->uri, r->user);

    return AUTHZ_DENIED;
}

static authz_status validuser_check_authorization(request_rec *r,
                                                  const char *require_args,
                                                  const void *parsed_require_args)
{
    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    return AUTHZ_GRANTED;
}

static authz_status group_check_authorization(request_rec *r,
                                              const char *require_args,
                                              const void *parsed_require_args)
{
    auth_plain_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                 &auth_plain_module);
    const char *t, *w;
    apr_table_t *grpstatus;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!(conf->auth_grpfile)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "No AuthPlainGroupFile was specified in the "
                      "configuration");
        return AUTHZ_DENIED;
    }

    grpstatus = plain_groups_for_user(r->pool, r->user, conf->auth_grpfile);

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (apr_table_get(grpstatus, w)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: user %s not allowed access",
                  r->uri, r->user);

    return AUTHZ_DENIED;
}

static const authn_provider authn_plain_provider =
{
    &check_plain_pw,
    NULL,
};

static const authz_provider authz_user_provider =
{
    &user_check_authorization,
    NULL,
};

static const authz_provider authz_validuser_provider =
{
    &validuser_check_authorization,
    NULL,
};

static const authz_provider authz_group_provider =
{
    &group_check_authorization,
    NULL,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "plain",
                              AUTHN_PROVIDER_VERSION,
                              &authn_plain_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_user_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-user",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_validuser_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_group_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA auth_plain_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_plain_dir_config,     /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    auth_plain_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
