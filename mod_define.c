/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
**  mod_define.c - Apache module for configuration defines ($xxx)
**
**  Copyright (c) 2011 W. Kleedorfer <wkleedorfer@gmail.com>
**  Copyright (c) 2006 Rainer Jung <rainer.jung@kippdata.de>
**  Copyright (c) 1998-2000 Ralf S. Engelschall <rse@engelschall.com>
**  Copyright (c) 1998-2000 Christian Reiber <chrei@en.muc.de>
**
*/

/*
 *  $Id: mod_define.c,v 1.4 2006/10/11 01:28:35 jung Exp $
 *
 *  HISTORY
 *
 *  v1.0: Originally written in December 1998 by
 *        Ralf S. Engelschall <rse@engelschall.com> and
 *        Christian Reiber <chrei@en.muc.de>
 *
 *  v1.1: Completely Overhauled in August 1999 by
 *        Ralf S. Engelschall <rse@engelschall.com>
 *
 *  v2.0: Ported for Apache 2.0 and 2.2 in August 2006 by
 *        Rainer Jung <rainer.jung@kippdata.de>
 *
 *  v2.1: Minor fixes in October 2006 by
 *        Rainer Jung <rainer.jung@kippdata.de>
 *
 *  v2.2: Added file scope to the variables in Feb. 2011
 *        W. Kleedorfer <wkleedorfer@gmail.com>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "apr_strings.h"
#include "apr_lib.h"

module AP_MODULE_DECLARE_DATA define_module;

/*
 * The global table of defines
 */

static apr_table_t *tDefines   = NULL;   /* global table of defines */
static int    bOnceSeenADefine = FALSE;  /* optimization flag */

/*
 * Forward declaration
 */
static int   DefineIndex      (apr_pool_t *, const char *, char *, int *, int *, char **);
static char *DefineFetch      (apr_pool_t *, const char *, char *);
static char *DefineExpand     (apr_pool_t *, char *, int, char *);
static void  DefineInit       (apr_pool_t *);
static apr_status_t  DefineCleanup (void *);
static int   DefineRewriteHook(apr_pool_t *pconf, apr_pool_t *plog,
                               ap_directive_t *current);
static int   DefineWalkConfigSub(apr_pool_t *pconf, apr_pool_t *plog,
                                 ap_directive_t *current);
static int   DefineWalkConfig(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp);

/*
 * Character classes for scanner function
 */
typedef enum {
    CC_ESCAPE, CC_DOLLAR, CC_BRACEOPEN, CC_BRACECLOSE,
    CC_IDCHAR1, CC_IDCHAR, CC_OTHER, CC_EOS
} CharClass;

/*
 * Scanner states for scanner function
 */
typedef enum {
    SS_NONE, SS_SKIP, SS_DOLLAR, SS_TOKEN_BRACED,
    SS_TOKEN_UNBRACED, SS_ERROR, SS_FOUND
} ScanState;

/*
 * Default meta characters
 */
#define DEFAULT_MC_ESCAPE      "\\"
#define DEFAULT_MC_DOLLAR      "$"
#define DEFAULT_MC_BRACEOPEN   "{"
#define DEFAULT_MC_BRACECLOSE  "}"

/*
 * Scanner for variable constructs $xxx and ${xxx}
 */
static int DefineIndex(apr_pool_t *p, const char *pScope, char *cpLine, int *pos, int *len, char **cpVar)
{
    int rc;
    char *cp;
    char *cp2;
    CharClass cc;
    char cEscape;
    char cDefine;
    char cBraceOpen;
    char cBraceClose;
    char *cpError;
    ScanState s;

    cEscape = DEFAULT_MC_ESCAPE[0];
    if ((cp = DefineFetch(p, "mod_define", "escape")) != NULL)
        cEscape = cp[0];
    cDefine = DEFAULT_MC_DOLLAR[0];
    if ((cp = DefineFetch(p, "mod_define", "dollar")) != NULL)
        cDefine = cp[0];
    cBraceOpen = DEFAULT_MC_BRACEOPEN[0];
    if ((cp = DefineFetch(p, "mod_define", "braceopen")) != NULL)
        cBraceOpen = cp[0];
    cBraceClose = DEFAULT_MC_BRACECLOSE[0];
    if ((cp = DefineFetch(p, "mod_define", "braceclose")) != NULL)
        cBraceClose = cp[0];

    rc = 0;
    *len = 0;
    cc = CC_OTHER;
    s = SS_NONE;
    for (cp = cpLine+(*pos); cc != CC_EOS; cp++) {
        if (*cp == cEscape)
            cc = CC_ESCAPE;
        else if (*cp == cDefine)
            cc = CC_DOLLAR;
        else if (*cp == cBraceOpen)
            cc = CC_BRACEOPEN;
        else if (*cp == cBraceClose)
            cc = CC_BRACECLOSE;
        else if (apr_isalpha(*cp))
            cc = CC_IDCHAR1;
        else if (apr_isdigit(*cp) || *cp == '_' || *cp == ':' || *cp == '-')
            cc = CC_IDCHAR;
        else if (*cp == '\0')
            cc = CC_EOS;
        else
            cc = CC_OTHER;
        switch (s) {
            case SS_NONE:
                switch (cc) {
                    case CC_ESCAPE:
                        s = SS_SKIP;
                        break;
                    case CC_DOLLAR:
                        s = SS_DOLLAR;
                        break;
                    default:
                        break;
                }
                break;
            case SS_SKIP:
                s = SS_NONE;
                continue;
                break;
            case SS_DOLLAR:
                switch (cc) {
                    case CC_BRACEOPEN:
                        s = SS_TOKEN_BRACED;
                        *pos = cp-cpLine-1;
                        (*len) = 2;
                        *cpVar = cp+1;
                        break;
                    case CC_IDCHAR1:
                        s = SS_TOKEN_UNBRACED;
                        *pos = cp-cpLine-1;
                        (*len) = 2;
                        *cpVar = cp;
                        break;
                    case CC_ESCAPE:
                        s = SS_SKIP;
                        break;
                    default:
                        s = SS_NONE;
                        break;
                }
                break;
            case SS_TOKEN_BRACED:
                switch (cc) {
                    case CC_IDCHAR1:
                    case CC_IDCHAR:
                        (*len)++;
                        break;
                    case CC_BRACECLOSE:
                        (*len)++;
                        cp2 = apr_palloc(p, cp-*cpVar+1);
                        apr_cpystrn(cp2, *cpVar, cp-*cpVar+1);
                        *cpVar = cp2;
                        s = SS_FOUND;
                        break;
                    default:
                        cpError = apr_psprintf(p, "Illegal character '%c' in identifier", *cp);
                        s = SS_ERROR;
                        break;
                }
                break;
            case SS_TOKEN_UNBRACED:
                switch (cc) {
                    case CC_IDCHAR1:
                    case CC_IDCHAR:
                        (*len)++;
                        break;
                    default:
                        cp2 = apr_palloc(p, cp-*cpVar+1);
                        apr_cpystrn(cp2, *cpVar, cp-*cpVar+1);
                        *cpVar = cp2;
                        s = SS_FOUND;
                        break;
                }
                break;
            case SS_FOUND:
            case SS_ERROR:
                break;
        }
        if (s == SS_ERROR) {
            fprintf(stderr, "Error: %s\n", cpError);
            break;
        }
        else if (s == SS_FOUND) {
            rc = 1;
            break;
        }
    }
    return rc;
}

/*
 * Since mod_define reads all its vars before parsing starts, if you have more than one of each var
 * (i.e. in your VirtualHost files) then only the last one would be used, instead of each define in its
 * own file. to counter this a scope filename::varname is added.
 */
static char *CreateNewVarName(const char *cpVar, const char *pScope, apr_pool_t *p)
{
    int pos = strcspn(cpVar, ":");
    int varlen = strlen(cpVar);

    // check if ":" is in the varname and there is enough space for a second ":" and at least one char
    if (pos < (varlen - 2) && cpVar[pos + 1] == ':')
    {
	// obviously there is already a scope there
	pScope = NULL;
    }

    char *newname; 
    if (pScope != NULL)
    {
        // allocate some memory from the pool
        // enough so filename::varname (plus trailing zero) fits
        newname = apr_palloc(p, strlen(cpVar) + strlen(pScope) + 3);
	strcpy(newname, pScope);
	strcat(newname, "::");
	strcat(newname, cpVar);
    }
    else
    {
        // if there is no filename just keep using the old names
        newname = apr_palloc(p, strlen(cpVar) + 1);
	strcpy(newname, cpVar);
    }
    return newname;
}


/*
 * Determine the value of a variable
 */
static char *DefineFetch(apr_pool_t *p, const char *pScope, char *cpVar)
{
    char *cpVal;
    char *cpNewName;

    // check if the scope is available
    if (pScope != NULL && strlen(pScope) > 0)
	cpNewName = CreateNewVarName(cpVar, pScope, p);
    else
	cpNewName = CreateNewVarName(cpVar, NULL, p);

    /* first try out table */
    if ((cpVal = (char *)apr_table_get(tDefines, cpNewName)) != NULL)
        return cpVal;
    /* second try the environment */
    if ((cpVal = getenv(cpVar)) != NULL)
        return cpVal;
    return NULL;
}

/*
 * Expand a variable
 */
static char *DefineExpand(apr_pool_t *p, char *cpToken, int tok_len, char *cpVal)
{
    char *cp;
    int val_len, rest_len;

    val_len  = strlen(cpVal);
    rest_len = strlen(cpToken+tok_len);
    if (val_len < tok_len)
        memcpy(cpToken+val_len, cpToken+tok_len, rest_len+1);
    else if (val_len > tok_len)
        for (cp = cpToken+strlen(cpToken); cp > cpToken+tok_len-1; cp--)
            *(cp+(val_len-tok_len)) = *cp;
    memcpy(cpToken, cpVal, val_len);
    return NULL;
}

/*
 * This routine is called before the server processes the configuration
 * files.
 */
static int DefineWalkConfig(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp)
{

    /* runtime optimization */
    if (!bOnceSeenADefine)
        return OK;

    DefineWalkConfigSub(pconf, plog, ap_conftree);

    return OK;
}


/*
 * This routine is called to patch the variables recursively.
 */
static int DefineWalkConfigSub(apr_pool_t *pconf, apr_pool_t *plog,
                               ap_directive_t *current)
{

    /* scan through all directives, executing each one */

    if ( current != NULL ) {
        DefineRewriteHook(pconf, plog, current);
        if ( current->first_child != NULL ) {
            DefineWalkConfigSub(pconf, plog, current->first_child);
        }
        if ( current->next != NULL ) {
            DefineWalkConfigSub(pconf, plog, current->next);
        }
    }

    return OK;
}


/*
 * This routine is called to patch the variables
 * into one directive.
 */
static int DefineRewriteHook(apr_pool_t *pconf, apr_pool_t *plog,
                             ap_directive_t *current)
{

    char *cpBuf;
    char *cpLine;
    int pos;
    int len;
    char *cpError;
    char *cpVar;
    char *cpVal;
    const char *pFilename = current?current->filename:NULL;

        /*
         * Search for:
         *  ....\$[a-zA-Z][:_a-zA-Z0-9]*....
         *  ....\${[a-zA-Z][:_a-zA-Z0-9]*}....
         */
        cpBuf = NULL;
        cpLine = (char *)current->args;
        pos = 0;
        while (DefineIndex(pconf, pFilename, cpLine, &pos, &len, &cpVar)) {

#ifdef DEFINE_DEBUG
            {
            char prefix[1024];
            char marker[1024];
            int i;
            for (i = 0; i < pos; i++)
                prefix[i] = ' ';
            prefix[i] = '\0';
            for (i = 0; i < len; i++)
                marker[i] = '^';
            marker[i] = '\0';
            fprintf(stderr,
                    "Found variable `%s' (pos: %d, len: %d)\n"
                    "  %s\n"
                    "  %s%s\n",
                    cpVar, pos, len, cpLine, prefix, marker);
            }
#endif
            if (cpBuf == NULL) {
                cpBuf = apr_palloc(pconf, MAX_STRING_LEN);
                apr_cpystrn(cpBuf, current->args, MAX_STRING_LEN);
                cpLine = cpBuf;
            }
            if ((cpVal = DefineFetch(pconf, pFilename, cpVar)) == NULL) {
                ap_log_perror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, plog,
                             "mod_define: Variable '%s' not defined: file %s, line %d",
                             cpVar, current->filename,
                             current->line_num);
                cpBuf = NULL;
                break;
            }
            if ((cpError = DefineExpand(pconf, cpLine+pos, len, cpVal)) != NULL) {
                ap_log_perror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, plog,
                             "mod_define: %s: file %s, line %d",
                             cpError, current->filename,
                             current->line_num);
                cpBuf = NULL;
                break;
            }
        }
        if ( cpBuf ) {
            current->args = cpBuf;
        }

    return OK;
}

/*
 * Implementation of the `Define' configuration directive
 */
static const char *cmd_define(cmd_parms *cmd, void *config,
                              const char *cpVar, const char *cpVal)
{
    char *cpNewName = NULL;
    if (tDefines == NULL)
        DefineInit(cmd->pool);

    // due to lack of documentation i am not sure when what parameters are actually
    // valid, so this is me being careful
    if (cmd != NULL && cmd->config_file != NULL)
        cpNewName = CreateNewVarName(cpVar, cmd->config_file->name, cmd->pool);
    else if (cmd != NULL)
        cpNewName = CreateNewVarName(cpVar, NULL, cmd->pool);
    else
	cpNewName = (char*)cpVar;

    apr_table_set(tDefines, cpNewName, cpVal);
    bOnceSeenADefine = TRUE;
    return NULL;
}

/*
 * Module Initialization
 */

static void DefineInit(apr_pool_t *p)
{
    tDefines = apr_table_make(p, 10);
    /* predefine delimiters */
    apr_table_set(tDefines, CreateNewVarName("escape", "mod_define", p), DEFAULT_MC_ESCAPE);
    apr_table_set(tDefines, "mod_define::dollar", DEFAULT_MC_DOLLAR);
    apr_table_set(tDefines, "mod_define::open",   DEFAULT_MC_BRACEOPEN);
    apr_table_set(tDefines, "mod_define::close",  DEFAULT_MC_BRACECLOSE);
    apr_table_set(tDefines, "mod_define::empty",  "");
    apr_pool_cleanup_register(p, NULL, DefineCleanup, apr_pool_cleanup_null);
    return;
}

/*
 * Module Cleanup
 */

static apr_status_t DefineCleanup(void *data)
{
    /* reset private variables when config pool is cleared */
    tDefines         = NULL;
    bOnceSeenADefine = FALSE;
    return APR_SUCCESS;
}

/*
 * Module Directive lists
 */
static const command_rec DefineDirectives[] = {
    AP_INIT_TAKE2("Define", cmd_define, NULL, RSRC_CONF|ACCESS_CONF|EXEC_ON_READ,
      "Define a configuration variable"),
    { NULL }
};

static void define_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(DefineWalkConfig, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA define_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                 /* create per-dir    config structures */
    NULL,                 /* merge  per-dir    config structures */
    NULL,                 /* create per-server config structures */
    NULL,                 /* merge  per-server config structures */
    DefineDirectives,     /* table of config file commands       */
    define_register_hooks /* register hooks */
};
