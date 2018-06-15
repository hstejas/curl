/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <limits.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#endif

#include "urldata.h"
#include "url.h"
#include "progress.h"
#include "content_encoding.h"
#include "strcase.h"
#include "share.h"
#include "vtls/vtls.h"
#include "warnless.h"
#include "sendf.h"
#include "http2.h"
#include "setopt.h"
#include "multiif.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_setstropt(char **charp, const char *s)
{
  /* Release the previous storage at `charp' and replace by a dynamic storage
     copy of `s'. Return CURLE_OK or CURLE_OUT_OF_MEMORY. */

  Curl_safefree(*charp);

  if(s) {
    char *str = strdup(s);

    if(!str)
      return CURLE_OUT_OF_MEMORY;

    *charp = str;
  }

  return CURLE_OK;
}

static CURLcode setstropt_userpwd(char *option, char **userp, char **passwdp)
{
  CURLcode result = CURLE_OK;
  char *user = NULL;
  char *passwd = NULL;

  /* Parse the login details if specified. It not then we treat NULL as a hint
     to clear the existing data */
  if(option) {
    result = Curl_parse_login_details(option, strlen(option),
                                      (userp ? &user : NULL),
                                      (passwdp ? &passwd : NULL),
                                      NULL);
  }

  if(!result) {
    /* Store the username part of option if required */
    if(userp) {
      if(!user && option && option[0] == ':') {
        /* Allocate an empty string instead of returning NULL as user name */
        user = strdup("");
        if(!user)
          result = CURLE_OUT_OF_MEMORY;
      }

      Curl_safefree(*userp);
      *userp = user;
    }

    /* Store the password part of option if required */
    if(passwdp) {
      Curl_safefree(*passwdp);
      *passwdp = passwd;
    }
  }

  return result;
}

static void debugPrintLong(struct Curl_easy *data, const char* option,
                      long param)
{
    char print_buffer[2048 + 1];
    print_buffer[2048] = 0;
    snprintf(print_buffer, sizeof(print_buffer), "setopt(%s, %d)\n", option, param);
    Curl_debug(data, CURLINFO_OPTIONS, print_buffer, strlen(print_buffer));
}

static void debugPrintStr(struct Curl_easy *data, const char* option,
                      char* param)
{
    char print_buffer[2048 + 1];
    print_buffer[2048] = 0;
    snprintf(print_buffer, sizeof(print_buffer), "setopt(%s, %s)\n", option, param);
    Curl_debug(data, CURLINFO_OPTIONS, print_buffer, strlen(print_buffer));
}

static void debugPrintObj(struct Curl_easy *data, const char* option,
                      void* param)
{
    char print_buffer[2048 + 1];
    print_buffer[2048] = 0;
    snprintf(print_buffer, sizeof(print_buffer), "setopt(%s, %p)\n", option, param);
    Curl_debug(data, CURLINFO_OPTIONS, print_buffer, strlen(print_buffer));
}

static void debugPrintOffT(struct Curl_easy *data, const char* option,
                       curl_off_t param)
{
    char print_buffer[2048 + 1];
    print_buffer[2048] = 0;
    snprintf(print_buffer, sizeof(print_buffer), "setopt(%s, %p)\n", option, param);
    Curl_debug(data, CURLINFO_OPTIONS, print_buffer, strlen(print_buffer));
}

#define C_SSLVERSION_VALUE(x) (x & 0xffff)
#define C_SSLVERSION_MAX_VALUE(x) (x & 0xffff0000)

CURLcode Curl_vsetopt(struct Curl_easy *data, CURLoption option,
                      va_list param)
{
  char *argptr;
  CURLcode result = CURLE_OK;
  long arg;

  switch(option) {
  case CURLOPT_DNS_CACHE_TIMEOUT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_DNS_CACHE_TIMEOUT", param_in);

    arg = param_in;
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.dns_cache_timeout = arg;
    break;
  }
  case CURLOPT_DNS_USE_GLOBAL_CACHE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_DNS_USE_GLOBAL_CACHE", param_in);

    /* remember we want this enabled */
    arg = param_in;
    data->set.global_dns_cache = (0 != arg) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_SSL_CIPHER_LIST:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSL_CIPHER_LIST", param_in);

    /* set a list of cipher we want to use in the SSL connection */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CIPHER_LIST_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_SSL_CIPHER_LIST:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_SSL_CIPHER_LIST", param_in);

    /* set a list of cipher we want to use in the SSL connection for proxy */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CIPHER_LIST_PROXY],
                            param_in);
    break;
  }

  case CURLOPT_TLS13_CIPHERS:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_TLS13_CIPHERS", param_in);

    if(Curl_ssl_tls13_ciphersuites()) {
      /* set preferred list of TLS 1.3 cipher suites */
      result = Curl_setstropt(&data->set.str[STRING_SSL_CIPHER13_LIST_ORIG],
                              param_in);
    }
    else
      return CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_PROXY_TLS13_CIPHERS:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_TLS13_CIPHERS", param_in);

    if(Curl_ssl_tls13_ciphersuites()) {
      /* set preferred list of TLS 1.3 cipher suites for proxy */
      result = Curl_setstropt(&data->set.str[STRING_SSL_CIPHER13_LIST_PROXY],
                              param_in);
    }
    else
      return CURLE_NOT_BUILT_IN;
    break;
  }

  case CURLOPT_RANDOM_FILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_RANDOM_FILE", param_in);

    /*
     * This is the path name to a file that contains random data to seed
     * the random SSL stuff with. The file is only used for reading.
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_RANDOM_FILE],
                            param_in);
    break;
  }
  case CURLOPT_EGDSOCKET:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_EGDSOCKET", param_in);

    /*
     * The Entropy Gathering Daemon socket pathname
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_EGDSOCKET],
                            param_in);
    break;
  }
  case CURLOPT_MAXCONNECTS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_MAXCONNECTS", param_in);

    /*
     * Set the absolute number of maximum simultaneous alive connection that
     * libcurl is allowed to have.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.maxconnects = arg;
    break;
  }
  case CURLOPT_FORBID_REUSE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FORBID_REUSE", param_in);

    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    data->set.reuse_forbid = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_FRESH_CONNECT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FRESH_CONNECT", param_in);

    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    data->set.reuse_fresh = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_VERBOSE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_VERBOSE", param_in);

    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    data->set.verbose = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_HEADER:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HEADER", param_in);

    /*
     * Set to include the header in the general data output stream.
     */
    data->set.include_header = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_NOPROGRESS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NOPROGRESS", param_in);

    /*
     * Shut off the internal supported progress meter
     */
    data->set.hide_progress = (0 != param_in) ? TRUE : FALSE;
    if(data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else
      data->progress.flags &= ~PGRS_HIDE;
    break;
  }
  case CURLOPT_NOBODY:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NOBODY", param_in);

    /*
     * Do not include the body part in the output data stream.
     */
    data->set.opt_no_body = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_FAILONERROR:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FAILONERROR", param_in);

    /*
     * Don't output the >=400 error code HTML-page, but instead only
     * return error.
     */
    data->set.http_fail_on_error = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_KEEP_SENDING_ON_ERROR:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_KEEP_SENDING_ON_ERROR", param_in);

    data->set.http_keep_sending_on_error = (0 != param_in) ?
      TRUE : FALSE;
    break;
  }
  case CURLOPT_UPLOAD:
  case CURLOPT_PUT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_UPLOAD", param_in);
    debugPrintLong(data, "CURLOPT_PUT", param_in);

    /*
     * We want to sent data to the remote host. If this is HTTP, that equals
     * using the PUT request.
     */
    data->set.upload = (0 != param_in) ? TRUE : FALSE;
    if(data->set.upload) {
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->set.httpreq = HTTPREQ_PUT;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      /* In HTTP, the opposite of upload is GET (unless NOBODY is true as
         then this can be changed to HEAD later on) */
      data->set.httpreq = HTTPREQ_GET;
    break;
  }
  case CURLOPT_REQUEST_TARGET:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_REQUEST_TARGET", param_in);

    result = Curl_setstropt(&data->set.str[STRING_TARGET],
                            param_in);
    break;
  }
  case CURLOPT_FILETIME:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FILETIME", param_in);

    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using curl_easy_getinfo().
     */
    data->set.get_filetime = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_FTP_CREATE_MISSING_DIRS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_CREATE_MISSING_DIRS", param_in);

    /*
     * An FTP option that modifies an upload to create missing directories on
     * the server.
     */
    switch(param_in) {
    case 0:
      data->set.ftp_create_missing_dirs = 0;
      break;
    case 1:
      data->set.ftp_create_missing_dirs = 1;
      break;
    case 2:
      data->set.ftp_create_missing_dirs = 2;
      break;
    default:
      /* reserve other values for future use */
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;
  }
  case CURLOPT_SERVER_RESPONSE_TIMEOUT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SERVER_RESPONSE_TIMEOUT", param_in);
    /*
     * Option that specifies how quickly an server response must be obtained
     * before it is considered failure. For pingpong protocols.
     */
    if((param_in >= 0) && (param_in <= (INT_MAX/1000)))
      data->set.server_response_timeout = param_in * 1000;
    else
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }
  case CURLOPT_TFTP_NO_OPTIONS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TFTP_NO_OPTIONS", param_in);

    /*
     * Option that prevents libcurl from sending TFTP option requests to the
     * server.
     */
    data->set.tftp_no_options = param_in != 0;
    break;
  }
  case CURLOPT_TFTP_BLKSIZE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TFTP_BLKSIZE", param_in);

    /*
     * TFTP option that specifies the block size to use for data transmission.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.tftp_blksize = arg;
    break;
  }
  case CURLOPT_DIRLISTONLY:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_DIRLISTONLY", param_in);

    /*
     * An option that changes the command to one that asks for a list
     * only, no file info details.
     */
    data->set.ftp_list_only = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_APPEND:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_APPEND", param_in);

    /*
     * We want to upload and append to an existing file.
     */
    data->set.ftp_append = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_FTP_FILEMETHOD:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_FILEMETHOD", param_in);

    /*
     * How do access files over FTP.
     */
    arg = param_in;
    if((arg < CURLFTPMETHOD_DEFAULT) || (arg > CURLFTPMETHOD_SINGLECWD))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.ftp_filemethod = (curl_ftpfile)arg;
    break;
  }
  case CURLOPT_NETRC:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NETRC", param_in);

    /*
     * Parse the $HOME/.netrc file
     */
    arg = param_in;
    if((arg < CURL_NETRC_IGNORED) || (arg > CURL_NETRC_REQUIRED))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.use_netrc = (enum CURL_NETRC_OPTION)arg;
    break;
  }
  case CURLOPT_NETRC_FILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_NETRC_FILE", param_in);

    /*
     * Use this file instead of the $HOME/.netrc file
     */
    result = Curl_setstropt(&data->set.str[STRING_NETRC_FILE],
                            param_in);
    break;
  }
  case CURLOPT_TRANSFERTEXT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TRANSFERTEXT", param_in);

    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    data->set.prefer_ascii = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_TIMECONDITION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TIMECONDITION", param_in);

    /*
     * Set HTTP time condition. This must be one of the defines in the
     * curl/curl.h header file.
     */
    arg = param_in;
    if((arg < CURL_TIMECOND_NONE) || (arg > CURL_TIMECOND_LASTMOD))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.timecondition = (curl_TimeCond)arg;
    break;
  }
  case CURLOPT_TIMEVALUE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TIMEVALUE", param_in);

    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)param_in;
    break;
  }

  case CURLOPT_TIMEVALUE_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_TIMEVALUE_LARGE", param_in);

    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)param_in;
    break;
  }

  case CURLOPT_SSLVERSION:
  case CURLOPT_PROXY_SSLVERSION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSLVERSION", param_in);
    debugPrintLong(data, "CURLOPT_PROXY_SSLVERSION", param_in);

    /*
     * Set explicit SSL version to try to connect with, as some SSL
     * implementations are lame.
     */
#ifdef USE_SSL
    {
      long version, version_max;
      struct ssl_primary_config *primary = (option == CURLOPT_SSLVERSION ?
                                            &data->set.ssl.primary :
                                            &data->set.proxy_ssl.primary);

      arg = param_in;

      version = C_SSLVERSION_VALUE(arg);
      version_max = C_SSLVERSION_MAX_VALUE(arg);

      if(version < CURL_SSLVERSION_DEFAULT ||
         version >= CURL_SSLVERSION_LAST ||
         version_max < CURL_SSLVERSION_MAX_NONE ||
         version_max >= CURL_SSLVERSION_MAX_LAST)
        return CURLE_BAD_FUNCTION_ARGUMENT;

      primary->version = version;
      primary->version_max = version_max;
    }
#else
    result = CURLE_UNKNOWN_OPTION;
#endif
    break;
  }

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_AUTOREFERER:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_AUTOREFERER", param_in);

    /*
     * Switch on automatic referer that gets set if curl follows locations.
     */
    data->set.http_auto_referer = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_ACCEPT_ENCODING:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_ACCEPT_ENCODING", param_in);

    /*
     * String to use at the value of Accept-Encoding header.
     *
     * If the encoding is set to "" we use an Accept-Encoding header that
     * encompasses all the encodings we support.
     * If the encoding is set to NULL we don't send an Accept-Encoding header
     * and ignore an received Content-Encoding header.
     *
     */
    argptr = param_in;
    if(argptr && !*argptr) {
      argptr = Curl_all_content_encodings();
      if(!argptr)
        result = CURLE_OUT_OF_MEMORY;
      else {
        result = Curl_setstropt(&data->set.str[STRING_ENCODING], argptr);
        free(argptr);
      }
    }
    else
      result = Curl_setstropt(&data->set.str[STRING_ENCODING], argptr);
    break;
  }

  case CURLOPT_TRANSFER_ENCODING:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TRANSFER_ENCODING", param_in);

    data->set.http_transfer_encoding = (0 != param_in) ?
      TRUE : FALSE;
    break;
  }

  case CURLOPT_FOLLOWLOCATION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FOLLOWLOCATION", param_in);

    /*
     * Follow Location: header hints on a HTTP-server.
     */
    data->set.http_follow_location = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_UNRESTRICTED_AUTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_UNRESTRICTED_AUTH", param_in);

    /*
     * Send authentication (user+password) when following locations, even when
     * hostname changed.
     */
    data->set.allow_auth_to_other_hosts =
      (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_MAXREDIRS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_MAXREDIRS", param_in);

    /*
     * The maximum amount of hops you allow curl to follow Location:
     * headers. This should mostly be used to detect never-ending loops.
     */
    arg = param_in;
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.maxredirs = arg;
    break;
  }

  case CURLOPT_POSTREDIR:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_POSTREDIR", param_in);

    /*
     * Set the behaviour of POST when redirecting
     * CURL_REDIR_GET_ALL - POST is changed to GET after 301 and 302
     * CURL_REDIR_POST_301 - POST is kept as POST after 301
     * CURL_REDIR_POST_302 - POST is kept as POST after 302
     * CURL_REDIR_POST_303 - POST is kept as POST after 303
     * CURL_REDIR_POST_ALL - POST is kept as POST after 301, 302 and 303
     * other - POST is kept as POST after 301 and 302
     */
    arg = param_in;
    if(arg < CURL_REDIR_GET_ALL)
      /* no return error on too high numbers since the bitmask could be
         extended in a future */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.keep_post = arg & CURL_REDIR_POST_ALL;
    break;
  }

  case CURLOPT_POST:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_POST", param_in);

    /* Does this option serve a purpose anymore? Yes it does, when
       CURLOPT_POSTFIELDS isn't used and the POST data is read off the
       callback! */
    if(param_in) {
      data->set.httpreq = HTTPREQ_POST;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      data->set.httpreq = HTTPREQ_GET;
    break;
  }

  case CURLOPT_COPYPOSTFIELDS:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_COPYPOSTFIELDS", param_in);

    /*
     * A string with POST data. Makes curl HTTP POST. Even if it is NULL.
     * If needed, CURLOPT_POSTFIELDSIZE must have been set prior to
     *  CURLOPT_COPYPOSTFIELDS and not altered later.
     */
    argptr = param_in;

    if(!argptr || data->set.postfieldsize == -1)
      result = Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], argptr);
    else {
      /*
       *  Check that requested length does not overflow the size_t type.
       */

      if((data->set.postfieldsize < 0) ||
         ((sizeof(curl_off_t) != sizeof(size_t)) &&
          (data->set.postfieldsize > (curl_off_t)((size_t)-1))))
        result = CURLE_OUT_OF_MEMORY;
      else {
        char *p;

        (void) Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);

        /* Allocate even when size == 0. This satisfies the need of possible
           later address compare to detect the COPYPOSTFIELDS mode, and
           to mark that postfields is used rather than read function or
           form data.
        */
        p = malloc((size_t)(data->set.postfieldsize?
                            data->set.postfieldsize:1));

        if(!p)
          result = CURLE_OUT_OF_MEMORY;
        else {
          if(data->set.postfieldsize)
            memcpy(p, argptr, (size_t)data->set.postfieldsize);

          data->set.str[STRING_COPYPOSTFIELDS] = p;
        }
      }
    }

    data->set.postfields = data->set.str[STRING_COPYPOSTFIELDS];
    data->set.httpreq = HTTPREQ_POST;
    break;
  }

  case CURLOPT_POSTFIELDS:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_POSTFIELDS", param_in);

    /*
     * Like above, but use static data instead of copying it.
     */
    data->set.postfields = param_in;
    /* Release old copied data. */
    (void) Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
    data->set.httpreq = HTTPREQ_POST;
    break;
  }

  case CURLOPT_POSTFIELDSIZE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_POSTFIELDSIZE", param_in);

    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    if(param_in < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    if(data->set.postfieldsize < param_in &&
       data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      (void) Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = param_in;
    break;
  }

  case CURLOPT_POSTFIELDSIZE_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_POSTFIELDSIZE_LARGE", param_in);

    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    if(param_in < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    if(data->set.postfieldsize < param_in &&
       data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      (void) Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = param_in;
    break;
  }

  case CURLOPT_HTTPPOST:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_HTTPPOST", param_in);

    /*
     * Set to make us do HTTP POST
     */
    data->set.httppost = param_in;
    data->set.httpreq = HTTPREQ_POST_FORM;
    data->set.opt_no_body = FALSE; /* this is implied */
    break;
  }
#endif   /* CURL_DISABLE_HTTP */

  case CURLOPT_MIMEPOST:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_MIMEPOST", param_in);

    /*
     * Set to make us do MIME/form POST
     */
    result = Curl_mime_set_subparts(&data->set.mimepost,
                                    param_in, FALSE);
    if(!result) {
      data->set.httpreq = HTTPREQ_POST_MIME;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    break;
  }

  case CURLOPT_REFERER:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_REFERER", param_in);

    /*
     * String to set in the HTTP Referer: field.
     */
    if(data->change.referer_alloc) {
      Curl_safefree(data->change.referer);
      data->change.referer_alloc = FALSE;
    }
    result = Curl_setstropt(&data->set.str[STRING_SET_REFERER],
                            param_in);
    data->change.referer = data->set.str[STRING_SET_REFERER];
    break;
  }

  case CURLOPT_USERAGENT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_USERAGENT", param_in);

    /*
     * String to use in the HTTP User-Agent field
     */
    result = Curl_setstropt(&data->set.str[STRING_USERAGENT],
                            param_in);
    break;
  }

  case CURLOPT_HTTPHEADER:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_HTTPHEADER", param_in);

    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    data->set.headers = param_in;
    break;
  }

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_PROXYHEADER:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_PROXYHEADER", param_in);

    /*
     * Set a list with proxy headers to use (or replace internals with)
     *
     * Since CURLOPT_HTTPHEADER was the only way to set HTTP headers for a
     * long time we remain doing it this way until CURLOPT_PROXYHEADER is
     * used. As soon as this option has been used, if set to anything but
     * NULL, custom headers for proxies are only picked from this list.
     *
     * Set this option to NULL to restore the previous behavior.
     */
    data->set.proxyheaders = param_in;
    break;
  }

  case CURLOPT_HEADEROPT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HEADEROPT", param_in);

    /*
     * Set header option.
     */
    arg = param_in;
    data->set.sep_headers = (arg & CURLHEADER_SEPARATE)? TRUE: FALSE;
    break;
  }

  case CURLOPT_HTTP200ALIASES:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_HTTP200ALIASES", param_in);

    /*
     * Set a list of aliases for HTTP 200 in response header
     */
    data->set.http200aliases = param_in;
    break;
  }

#if !defined(CURL_DISABLE_COOKIES)
  case CURLOPT_COOKIE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_COOKIE", param_in);

    /*
     * Cookie string to send to the remote server in the request.
     */
    result = Curl_setstropt(&data->set.str[STRING_COOKIE],
                            param_in);
    break;
  }

  case CURLOPT_COOKIEFILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_COOKIEFILE", param_in);

    /*
     * Set cookie file to read and parse. Can be used multiple times.
     */
    argptr = (char *)param_in;
    if(argptr) {
      struct curl_slist *cl;
      /* append the cookie file name to the list of file names, and deal with
         them later */
      cl = curl_slist_append(data->change.cookielist, argptr);
      if(!cl) {
        curl_slist_free_all(data->change.cookielist);
        data->change.cookielist = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
      data->change.cookielist = cl; /* store the list for later use */
    }
    break;
  }

  case CURLOPT_COOKIEJAR:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_COOKIEJAR", param_in);

    /*
     * Set cookie file name to dump all cookies to when we're done.
     */
  {
    struct CookieInfo *newcookies;
    result = Curl_setstropt(&data->set.str[STRING_COOKIEJAR],
                            param_in);

    /*
     * Activate the cookie parser. This may or may not already
     * have been made.
     */
    newcookies = Curl_cookie_init(data, NULL, data->cookies,
                                  data->set.cookiesession);
    if(!newcookies)
      result = CURLE_OUT_OF_MEMORY;
    data->cookies = newcookies;
  }
  break;
  }

  case CURLOPT_COOKIESESSION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_COOKIESESSION", param_in);

    /*
     * Set this option to TRUE to start a new "cookie session". It will
     * prevent the forthcoming read-cookies-from-file actions to accept
     * cookies that are marked as being session cookies, as they belong to a
     * previous session.
     *
     * In the original Netscape cookie spec, "session cookies" are cookies
     * with no expire date set. RFC2109 describes the same action if no
     * 'Max-Age' is set and RFC2965 includes the RFC2109 description and adds
     * a 'Discard' action that can enforce the discard even for cookies that
     * have a Max-Age.
     *
     * We run mostly with the original cookie spec, as hardly anyone implements
     * anything else.
     */
    data->set.cookiesession = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_COOKIELIST:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_COOKIELIST", param_in);

    argptr = param_in;

    if(argptr == NULL)
      break;

    if(strcasecompare(argptr, "ALL")) {
      /* clear all cookies */
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearall(data->cookies);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    else if(strcasecompare(argptr, "SESS")) {
      /* clear session cookies */
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearsess(data->cookies);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    else if(strcasecompare(argptr, "FLUSH")) {
      /* flush cookies to file, takes care of the locking */
      Curl_flush_cookies(data, 0);
    }
    else if(strcasecompare(argptr, "RELOAD")) {
      /* reload cookies from file */
      Curl_cookie_loadfiles(data);
      break;
    }
    else {
      if(!data->cookies)
        /* if cookie engine was not running, activate it */
        data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);

      argptr = strdup(argptr);
      if(!argptr || !data->cookies) {
        result = CURLE_OUT_OF_MEMORY;
        free(argptr);
      }
      else {
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);

        if(checkprefix("Set-Cookie:", argptr))
          /* HTTP Header format line */
          Curl_cookie_add(data, data->cookies, TRUE, FALSE, argptr + 11, NULL,
                          NULL);

        else
          /* Netscape format line */
          Curl_cookie_add(data, data->cookies, FALSE, FALSE, argptr, NULL,
                          NULL);

        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
        free(argptr);
      }
    }

    break;
  }
#endif /* !CURL_DISABLE_COOKIES */

  case CURLOPT_HTTPGET:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTPGET", param_in);

    /*
     * Set to force us do HTTP GET
     */
    if(param_in) {
      data->set.httpreq = HTTPREQ_GET;
      data->set.upload = FALSE; /* switch off upload */
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    break;
  }

  case CURLOPT_HTTP_VERSION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTP_VERSION", param_in);

    /*
     * This sets a requested HTTP version to be used. The value is one of
     * the listed enums in curl/curl.h.
     */
    arg = param_in;
    if(arg < CURL_HTTP_VERSION_NONE)
      return CURLE_BAD_FUNCTION_ARGUMENT;
#ifndef USE_NGHTTP2
    if(arg >= CURL_HTTP_VERSION_2)
      return CURLE_UNSUPPORTED_PROTOCOL;
#else
    if(arg > CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif
    data->set.httpversion = arg;
    break;
  }

  case CURLOPT_EXPECT_100_TIMEOUT_MS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_EXPECT_100_TIMEOUT_MS", param_in);

    /*
     * Time to wait for a response to a HTTP request containing an
     * Expect: 100-continue header before sending the data anyway.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.expect_100_timeout = arg;
    break;
  }

#endif   /* CURL_DISABLE_HTTP */

  case CURLOPT_HTTPAUTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTPAUTH", param_in);

    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = param_in;

    if(auth == CURLAUTH_NONE) {
      data->set.httpauth = auth;
      break;
    }

    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    data->state.authhost.iestyle = (auth & CURLAUTH_DIGEST_IE) ? TRUE : FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; /* set standard digest bit */
      auth &= ~CURLAUTH_DIGEST_IE; /* unset ie digest bit */
    }

    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM;    /* no NTLM support */
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#elif !defined(NTLM_WB_ENABLED)
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#endif
#ifndef USE_SPNEGO
    auth &= ~CURLAUTH_NEGOTIATE; /* no Negotiate (SPNEGO) auth without
                                    GSS-API or SSPI */
#endif

    /* check if any auth bit lower than CURLAUTH_ONLY is still set */
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; /* no supported types left! */

    data->set.httpauth = auth;
  }
  break;
  }

  case CURLOPT_CUSTOMREQUEST:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_CUSTOMREQUEST", param_in);

    /*
     * Set a custom string to use as request
     */
    result = Curl_setstropt(&data->set.str[STRING_CUSTOMREQUEST],
                            param_in);

    /* we don't set
       data->set.httpreq = HTTPREQ_CUSTOM;
       here, we continue as if we were using the already set type
       and this just changes the actual request keyword */
    break;
  }

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_HTTPPROXYTUNNEL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTPPROXYTUNNEL", param_in);

    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    data->set.tunnel_thru_httpproxy = (0 != param_in) ?
      TRUE : FALSE;
    break;
  }

  case CURLOPT_PROXYPORT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXYPORT", param_in);

    /*
     * Explicitly set HTTP proxy port number.
     */
    arg = param_in;
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.proxyport = arg;
    break;
  }

  case CURLOPT_PROXYAUTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXYAUTH", param_in);

    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = param_in;

    if(auth == CURLAUTH_NONE) {
      data->set.proxyauth = auth;
      break;
    }

    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    data->state.authproxy.iestyle = (auth & CURLAUTH_DIGEST_IE) ? TRUE : FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; /* set standard digest bit */
      auth &= ~CURLAUTH_DIGEST_IE; /* unset ie digest bit */
    }
    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM;    /* no NTLM support */
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#elif !defined(NTLM_WB_ENABLED)
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#endif
#ifndef USE_SPNEGO
    auth &= ~CURLAUTH_NEGOTIATE; /* no Negotiate (SPNEGO) auth without
                                    GSS-API or SSPI */
#endif

    /* check if any auth bit lower than CURLAUTH_ONLY is still set */
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; /* no supported types left! */

    data->set.proxyauth = auth;
  }
  break;
  }

  case CURLOPT_PROXY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY", param_in);

    /*
     * Set proxy server:port to use as proxy.
     *
     * If the proxy is set to "" (and CURLOPT_SOCKS_PROXY is set to "" or NULL)
     * we explicitly say that we don't want to use a proxy
     * (even though there might be environment variables saying so).
     *
     * Setting it to NULL, means no proxy but allows the environment variables
     * to decide for us (if CURLOPT_SOCKS_PROXY setting it to NULL).
     */
    result = Curl_setstropt(&data->set.str[STRING_PROXY],
                            param_in);
    break;
  }

  case CURLOPT_PRE_PROXY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PRE_PROXY", param_in);

    /*
     * Set proxy server:port to use as SOCKS proxy.
     *
     * If the proxy is set to "" or NULL we explicitly say that we don't want
     * to use the socks proxy.
     */
    result = Curl_setstropt(&data->set.str[STRING_PRE_PROXY],
                            param_in);
    break;
  }

  case CURLOPT_PROXYTYPE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXYTYPE", param_in);

    /*
     * Set proxy type. HTTP/HTTP_1_0/SOCKS4/SOCKS4a/SOCKS5/SOCKS5_HOSTNAME
     */
    arg = param_in;
    if((arg < CURLPROXY_HTTP) || (arg > CURLPROXY_SOCKS5_HOSTNAME))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.proxytype = (curl_proxytype)arg;
    break;
  }

  case CURLOPT_PROXY_TRANSFER_MODE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXY_TRANSFER_MODE", param_in);

    /*
     * set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy
     */
    switch(param_in) {
    case 0:
      data->set.proxy_transfer_mode = FALSE;
      break;
    case 1:
      data->set.proxy_transfer_mode = TRUE;
      break;
    default:
      /* reserve other values for future use */
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;
  }
#endif   /* CURL_DISABLE_PROXY */

  case CURLOPT_SOCKS5_AUTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SOCKS5_AUTH", param_in);

    data->set.socks5auth = param_in;
    if(data->set.socks5auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
      result = CURLE_NOT_BUILT_IN;
    break;
  }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case CURLOPT_SOCKS5_GSSAPI_NEC:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SOCKS5_GSSAPI_NEC", param_in);

    /*
     * Set flag for NEC SOCK5 support
     */
    data->set.socks5_gssapi_nec = (0 != param_in) ? TRUE : FALSE;
    break;
  }
#endif

  case CURLOPT_SOCKS5_GSSAPI_SERVICE:
  case CURLOPT_PROXY_SERVICE_NAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SOCKS5_GSSAPI_SERVICE", param_in);
    debugPrintStr(data, "CURLOPT_PROXY_SERVICE_NAME", param_in);

    /*
     * Set proxy authentication service name for Kerberos 5 and SPNEGO
     */
    result = Curl_setstropt(&data->set.str[STRING_PROXY_SERVICE_NAME],
                            param_in);
    break;
  }

  case CURLOPT_SERVICE_NAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SERVICE_NAME", param_in);

    /*
     * Set authentication service name for DIGEST-MD5, Kerberos 5 and SPNEGO
     */
    result = Curl_setstropt(&data->set.str[STRING_SERVICE_NAME],
                            param_in);
    break;
  }

  case CURLOPT_HEADERDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_HEADERDATA", param_in);

    /*
     * Custom pointer to pass the header write callback function
     */
    data->set.writeheader = (void *)param_in;
    break;
  }
  case CURLOPT_ERRORBUFFER:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_ERRORBUFFER", param_in);

    /*
     * Error buffer provided by the caller to get the human readable
     * error string in.
     */
    data->set.errorbuffer = param_in;
    break;
  }
  case CURLOPT_WRITEDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_WRITEDATA", param_in);

    /*
     * FILE pointer to write to. Or possibly
     * used as argument to the write callback.
     */
    data->set.out = param_in;
    break;
  }
  case CURLOPT_FTPPORT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_FTPPORT", param_in);

    /*
     * Use FTP PORT, this also specifies which IP address to use
     */
    result = Curl_setstropt(&data->set.str[STRING_FTPPORT],
                            param_in);
    data->set.ftp_use_port = (data->set.str[STRING_FTPPORT]) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_USE_EPRT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_USE_EPRT", param_in);

    data->set.ftp_use_eprt = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_USE_EPSV:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_USE_EPSV", param_in);

    data->set.ftp_use_epsv = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_USE_PRET:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_USE_PRET", param_in);

    data->set.ftp_use_pret = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_SSL_CCC:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_SSL_CCC", param_in);

    arg = param_in;
    if((arg < CURLFTPSSL_CCC_NONE) || (arg > CURLFTPSSL_CCC_ACTIVE))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.ftp_ccc = (curl_ftpccc)arg;
    break;
  }

  case CURLOPT_FTP_SKIP_PASV_IP:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTP_SKIP_PASV_IP", param_in);

    /*
     * Enable or disable FTP_SKIP_PASV_IP, which will disable/enable the
     * bypass of the IP address in PASV responses.
     */
    data->set.ftp_skip_ip = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_READDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_READDATA", param_in);

    /*
     * FILE pointer to read the file to be uploaded from. Or possibly
     * used as argument to the read callback.
     */
    data->set.in_set = param_in;
    break;
  }
  case CURLOPT_INFILESIZE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_INFILESIZE", param_in);

    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    arg = param_in;
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.filesize = arg;
    break;
  }
  case CURLOPT_INFILESIZE_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_INFILESIZE_LARGE", param_in);

    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    if(param_in < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.filesize = param_in;
    break;
  }
  case CURLOPT_LOW_SPEED_LIMIT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_LOW_SPEED_LIMIT", param_in);

    /*
     * The low speed limit that if transfers are below this for
     * CURLOPT_LOW_SPEED_TIME, the transfer is aborted.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.low_speed_limit = arg;
    break;
  }
  case CURLOPT_MAX_SEND_SPEED_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_MAX_SEND_SPEED_LARGE", param_in);

    /*
     * When transfer uploads are faster then CURLOPT_MAX_SEND_SPEED_LARGE
     * bytes per second the transfer is throttled..
     */
    if(param_in < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.max_send_speed = param_in;
    break;
  }
  case CURLOPT_MAX_RECV_SPEED_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_MAX_RECV_SPEED_LARGE", param_in);

    /*
     * When receiving data faster than CURLOPT_MAX_RECV_SPEED_LARGE bytes per
     * second the transfer is throttled..
     */
    if(param_in < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.max_recv_speed = param_in;
    break;
  }
  case CURLOPT_LOW_SPEED_TIME:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_LOW_SPEED_TIME", param_in);

    /*
     * The low speed time that if transfers are below the set
     * CURLOPT_LOW_SPEED_LIMIT during this time, the transfer is aborted.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.low_speed_time = arg;
    break;
  }
  case CURLOPT_URL:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_URL", param_in);

    /*
     * The URL to fetch.
     */
    if(data->change.url_alloc) {
      /* the already set URL is allocated, free it first! */
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }
    result = Curl_setstropt(&data->set.str[STRING_SET_URL],
                            param_in);
    data->change.url = data->set.str[STRING_SET_URL];
    break;
  }
  case CURLOPT_PORT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PORT", param_in);

    /*
     * The port number to use when getting the URL
     */
    arg = param_in;
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.use_port = arg;
    break;
  }
  case CURLOPT_TIMEOUT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TIMEOUT", param_in);

    /*
     * The maximum time you allow curl to use for a single transfer
     * operation.
     */
    arg = param_in;
    if((arg >= 0) && (arg <= (INT_MAX/1000)))
      data->set.timeout = arg * 1000;
    else
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }

  case CURLOPT_TIMEOUT_MS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TIMEOUT_MS", param_in);

    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.timeout = arg;
    break;
  }

  case CURLOPT_CONNECTTIMEOUT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_CONNECTTIMEOUT", param_in);

    /*
     * The maximum time you allow curl to use to connect.
     */
    arg = param_in;
    if((arg >= 0) && (arg <= (INT_MAX/1000)))
      data->set.connecttimeout = arg * 1000;
    else
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }

  case CURLOPT_CONNECTTIMEOUT_MS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_CONNECTTIMEOUT_MS", param_in);

    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.connecttimeout = arg;
    break;
  }

  case CURLOPT_ACCEPTTIMEOUT_MS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_ACCEPTTIMEOUT_MS", param_in);

    /*
     * The maximum time you allow curl to wait for server connect
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.accepttimeout = arg;
    break;
  }

  case CURLOPT_USERPWD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_USERPWD", param_in);

    /*
     * user:password to use in the operation
     */
    result = setstropt_userpwd(param_in,
                               &data->set.str[STRING_USERNAME],
                               &data->set.str[STRING_PASSWORD]);
    break;
  }

  case CURLOPT_USERNAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_USERNAME", param_in);

    /*
     * authentication user name to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_USERNAME],
                            param_in);
    break;
  }

  case CURLOPT_PASSWORD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PASSWORD", param_in);

    /*
     * authentication password to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_PASSWORD],
                            param_in);
    break;
  }

  case CURLOPT_LOGIN_OPTIONS:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_LOGIN_OPTIONS", param_in);

    /*
     * authentication options to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_OPTIONS],
                            param_in);
    break;
  }

  case CURLOPT_XOAUTH2_BEARER:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_XOAUTH2_BEARER", param_in);

    /*
     * OAuth 2.0 bearer token to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_BEARER],
                            param_in);
    break;
  }

  case CURLOPT_POSTQUOTE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_POSTQUOTE", param_in);

    /*
     * List of RAW FTP commands to use after a transfer
     */
    data->set.postquote = param_in;
    break;
  }
  case CURLOPT_PREQUOTE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_PREQUOTE", param_in);

    /*
     * List of RAW FTP commands to use prior to RETR (Wesley Laxton)
     */
    data->set.prequote = param_in;
    break;
  }
  case CURLOPT_QUOTE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_QUOTE", param_in);

    /*
     * List of RAW FTP commands to use before a transfer
     */
    data->set.quote = param_in;
    break;
  }
  case CURLOPT_RESOLVE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_RESOLVE", param_in);

    /*
     * List of NAME:[address] names to populate the DNS cache with
     * Prefix the NAME with dash (-) to _remove_ the name from the cache.
     *
     * Names added with this API will remain in the cache until explicitly
     * removed or the handle is cleaned up.
     *
     * This API can remove any name from the DNS cache, but only entries
     * that aren't actually in use right now will be pruned immediately.
     */
    data->set.resolve = param_in;
    data->change.resolve = data->set.resolve;
    break;
  }
  case CURLOPT_PROGRESSFUNCTION:
  {
    curl_progress_callback param_in = va_arg(param, curl_progress_callback);
    debugPrintObj(data, "CURLOPT_PROGRESSFUNCTION", param_in);

    /*
     * Progress callback function
     */
    data->set.fprogress = param_in;
    if(data->set.fprogress)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */
    break;
  }

  case CURLOPT_XFERINFOFUNCTION:
  {
    curl_xferinfo_callback param_in = va_arg(param, curl_xferinfo_callback);
    debugPrintObj(data, "CURLOPT_XFERINFOFUNCTION", param_in);

    /*
     * Transfer info callback function
     */
    data->set.fxferinfo = param_in;
    if(data->set.fxferinfo)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */

    break;
  }

  case CURLOPT_PROGRESSDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_PROGRESSDATA", param_in);

    /*
     * Custom client data to pass to the progress callback
     */
    data->set.progress_client = param_in;
    break;
  }

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXYUSERPWD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXYUSERPWD", param_in);

    /*
     * user:password needed to use the proxy
     */
    result = setstropt_userpwd(param_in,
                               &data->set.str[STRING_PROXYUSERNAME],
                               &data->set.str[STRING_PROXYPASSWORD]);
    break;
  }
  case CURLOPT_PROXYUSERNAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXYUSERNAME", param_in);

    /*
     * authentication user name to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_PROXYUSERNAME],
                            param_in);
    break;
  }
  case CURLOPT_PROXYPASSWORD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXYPASSWORD", param_in);

    /*
     * authentication password to use in the operation
     */
    result = Curl_setstropt(&data->set.str[STRING_PROXYPASSWORD],
                            param_in);
    break;
  }
  case CURLOPT_NOPROXY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_NOPROXY", param_in);

    /*
     * proxy exception list
     */
    result = Curl_setstropt(&data->set.str[STRING_NOPROXY],
                            param_in);
    break;
  }
#endif

  case CURLOPT_RANGE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_RANGE", param_in);

    /*
     * What range of the file you want to transfer
     */
    result = Curl_setstropt(&data->set.str[STRING_SET_RANGE],
                            param_in);
    break;
  }
  case CURLOPT_RESUME_FROM:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_RESUME_FROM", param_in);

    /*
     * Resume transfer at the given file position
     */
    arg = param_in;
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.set_resume_from = arg;
    break;
  }
  case CURLOPT_RESUME_FROM_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_RESUME_FROM_LARGE", param_in);

    /*
     * Resume transfer at the given file position
     */
    if(param_in < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.set_resume_from = param_in;
    break;
  }
  case CURLOPT_DEBUGFUNCTION:
  {
    curl_debug_callback param_in = va_arg(param, curl_debug_callback);
    debugPrintObj(data, "CURLOPT_DEBUGFUNCTION", param_in);

    /*
     * stderr write callback.
     */
    data->set.fdebug = param_in;
    /*
     * if the callback provided is NULL, it'll use the default callback
     */
    break;
  }
  case CURLOPT_DEBUGDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_DEBUGDATA", param_in);

    /*
     * Set to a void * that should receive all error writes. This
     * defaults to CURLOPT_STDERR for normal operations.
     */
    data->set.debugdata = param_in;
    break;
  }
  case CURLOPT_STDERR:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_STDERR", param_in);

    /*
     * Set to a FILE * that should receive all error writes. This
     * defaults to stderr for normal operations.
     */
    data->set.err = va_arg(param, FILE *);
    if(!data->set.err)
      data->set.err = stderr;
    break;
  }
  case CURLOPT_HEADERFUNCTION:
  {
    curl_write_callback param_in = va_arg(param, curl_write_callback);
    debugPrintObj(data, "CURLOPT_HEADERFUNCTION", param_in);

    /*
     * Set header write callback
     */
    data->set.fwrite_header = param_in;
    break;
  }
  case CURLOPT_WRITEFUNCTION:
  {
    curl_write_callback param_in = va_arg(param, curl_write_callback);
    debugPrintObj(data, "CURLOPT_WRITEFUNCTION", param_in);

    /*
     * Set data write callback
     */
    data->set.fwrite_func = param_in;
    if(!data->set.fwrite_func) {
      data->set.is_fwrite_set = 0;
      /* When set to NULL, reset to our internal default function */
      data->set.fwrite_func = (curl_write_callback)fwrite;
    }
    else
      data->set.is_fwrite_set = 1;
    break;
  }
  case CURLOPT_READFUNCTION:
  {
    curl_read_callback param_in = va_arg(param, curl_read_callback);
    debugPrintObj(data, "CURLOPT_READFUNCTION", param_in);

    /*
     * Read data callback
     */
    data->set.fread_func_set = param_in;
    if(!data->set.fread_func_set) {
      data->set.is_fread_set = 0;
      /* When set to NULL, reset to our internal default function */
      data->set.fread_func_set = (curl_read_callback)fread;
    }
    else
      data->set.is_fread_set = 1;
    break;
  }
  case CURLOPT_SEEKFUNCTION:
  {
    curl_seek_callback param_in = va_arg(param, curl_seek_callback);
    debugPrintObj(data, "CURLOPT_SEEKFUNCTION", param_in);

    /*
     * Seek callback. Might be NULL.
     */
    data->set.seek_func = param_in;
    break;
  }
  case CURLOPT_SEEKDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_SEEKDATA", param_in);

    /*
     * Seek control callback. Might be NULL.
     */
    data->set.seek_client = param_in;
    break;
  }
  case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
  {
    curl_conv_callback param_in = va_arg(param, curl_conv_callback);
    debugPrintObj(data, "CURLOPT_CONV_FROM_NETWORK_FUNCTION", param_in);

    /*
     * "Convert from network encoding" callback
     */
    data->set.convfromnetwork = param_in;
    break;
  }
  case CURLOPT_CONV_TO_NETWORK_FUNCTION:
  {
    curl_conv_callback param_in = va_arg(param, curl_conv_callback);
    debugPrintObj(data, "CURLOPT_CONV_TO_NETWORK_FUNCTION", param_in);

    /*
     * "Convert to network encoding" callback
     */
    data->set.convtonetwork = param_in;
    break;
  }
  case CURLOPT_CONV_FROM_UTF8_FUNCTION:
  {
    curl_conv_callback param_in = va_arg(param, curl_conv_callback);
    debugPrintObj(data, "CURLOPT_CONV_FROM_UTF8_FUNCTION", param_in);

    /*
     * "Convert from UTF-8 encoding" callback
     */
    data->set.convfromutf8 = param_in;
    break;
  }
  case CURLOPT_IOCTLFUNCTION:
  {
    curl_ioctl_callback param_in = va_arg(param, curl_ioctl_callback);
    debugPrintObj(data, "CURLOPT_IOCTLFUNCTION", param_in);

    /*
     * I/O control callback. Might be NULL.
     */
    data->set.ioctl_func = param_in;
    break;
  }
  case CURLOPT_IOCTLDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_IOCTLDATA", param_in);

    /*
     * I/O control data pointer. Might be NULL.
     */
    data->set.ioctl_client = param_in;
    break;
  }
  case CURLOPT_SSLCERT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSLCERT", param_in);

    /*
     * String that holds file name of the SSL certificate to use
     */
    result = Curl_setstropt(&data->set.str[STRING_CERT_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_SSLCERT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_SSLCERT", param_in);

    /*
     * String that holds file name of the SSL certificate to use for proxy
     */
    result = Curl_setstropt(&data->set.str[STRING_CERT_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_SSLCERTTYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSLCERTTYPE", param_in);

    /*
     * String that holds file type of the SSL certificate to use
     */
    result = Curl_setstropt(&data->set.str[STRING_CERT_TYPE_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_SSLCERTTYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_SSLCERTTYPE", param_in);

    /*
     * String that holds file type of the SSL certificate to use for proxy
     */
    result = Curl_setstropt(&data->set.str[STRING_CERT_TYPE_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_SSLKEY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSLKEY", param_in);

    /*
     * String that holds file name of the SSL key to use
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_SSLKEY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_SSLKEY", param_in);

    /*
     * String that holds file name of the SSL key to use for proxy
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_SSLKEYTYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSLKEYTYPE", param_in);

    /*
     * String that holds file type of the SSL key to use
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_TYPE_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_SSLKEYTYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_SSLKEYTYPE", param_in);

    /*
     * String that holds file type of the SSL key to use for proxy
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_TYPE_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_KEYPASSWD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_KEYPASSWD", param_in);

    /*
     * String that holds the SSL or SSH private key password.
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_PASSWD_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_KEYPASSWD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_KEYPASSWD", param_in);

    /*
     * String that holds the SSL private key password for proxy.
     */
    result = Curl_setstropt(&data->set.str[STRING_KEY_PASSWD_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_SSLENGINE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSLENGINE", param_in);

    /*
     * String that holds the SSL crypto engine.
     */
    argptr = param_in;
    if(argptr && argptr[0])
      result = Curl_ssl_set_engine(data, argptr);
    break;
  }

  case CURLOPT_SSLENGINE_DEFAULT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSLENGINE_DEFAULT", param_in);

    /*
     * flag to set engine as default.
     */
    result = Curl_ssl_set_engine_default(data);
    break;
  }
  case CURLOPT_CRLF:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_CRLF", param_in);

    /*
     * Kludgy option to enable CRLF conversions. Subject for removal.
     */
    data->set.crlf = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_HAPROXYPROTOCOL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HAPROXYPROTOCOL", param_in);

    /*
     * Set to send the HAProxy Proxy Protocol header
     */
    data->set.haproxyprotocol = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_INTERFACE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_INTERFACE", param_in);

    /*
     * Set what interface or address/hostname to bind the socket to when
     * performing an operation and thus what from-IP your connection will use.
     */
    result = Curl_setstropt(&data->set.str[STRING_DEVICE],
                            param_in);
    break;
  }
  case CURLOPT_LOCALPORT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_LOCALPORT", param_in);

    /*
     * Set what local port to bind the socket to when performing an operation.
     */
    arg = param_in;
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.localport = curlx_sltous(arg);
    break;
  }
  case CURLOPT_LOCALPORTRANGE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_LOCALPORTRANGE", param_in);

    /*
     * Set number of local ports to try, starting with CURLOPT_LOCALPORT.
     */
    arg = param_in;
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.localportrange = curlx_sltosi(arg);
    break;
  }
  case CURLOPT_KRBLEVEL:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_KRBLEVEL", param_in);

    /*
     * A string that defines the kerberos security level.
     */
    result = Curl_setstropt(&data->set.str[STRING_KRB_LEVEL],
                            param_in);
    data->set.krb = (data->set.str[STRING_KRB_LEVEL]) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_GSSAPI_DELEGATION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_GSSAPI_DELEGATION", param_in);

    /*
     * GSS-API credential delegation bitmask
     */
    arg = param_in;
    if(arg < CURLGSSAPI_DELEGATION_NONE)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.gssapi_delegation = arg;
    break;
  }
  case CURLOPT_SSL_VERIFYPEER:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_VERIFYPEER", param_in);

    /*
     * Enable peer SSL verifying.
     */
    data->set.ssl.primary.verifypeer = (0 != param_in) ?
      TRUE : FALSE;

    /* Update the current connection ssl_config. */
    if(data->easy_conn) {
      data->easy_conn->ssl_config.verifypeer =
        data->set.ssl.primary.verifypeer;
    }
    break;
  }
  case CURLOPT_PROXY_SSL_VERIFYPEER:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXY_SSL_VERIFYPEER", param_in);

    /*
     * Enable peer SSL verifying for proxy.
     */
    data->set.proxy_ssl.primary.verifypeer =
      (0 != param_in)?TRUE:FALSE;

    /* Update the current connection proxy_ssl_config. */
    if(data->easy_conn) {
      data->easy_conn->proxy_ssl_config.verifypeer =
        data->set.proxy_ssl.primary.verifypeer;
    }
    break;
  }
  case CURLOPT_SSL_VERIFYHOST:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_VERIFYHOST", param_in);

    /*
     * Enable verification of the host name in the peer certificate
     */
    arg = param_in;

    /* Obviously people are not reading documentation and too many thought
       this argument took a boolean when it wasn't and misused it. We thus ban
       1 as a sensible input and we warn about its use. Then we only have the
       2 action internally stored as TRUE. */

    if(1 == arg) {
      failf(data, "CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.ssl.primary.verifyhost = (0 != arg) ? TRUE : FALSE;

    /* Update the current connection ssl_config. */
    if(data->easy_conn) {
      data->easy_conn->ssl_config.verifyhost =
        data->set.ssl.primary.verifyhost;
    }
    break;
  }
  case CURLOPT_PROXY_SSL_VERIFYHOST:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXY_SSL_VERIFYHOST", param_in);

    /*
     * Enable verification of the host name in the peer certificate for proxy
     */
    arg = param_in;

    /* Obviously people are not reading documentation and too many thought
       this argument took a boolean when it wasn't and misused it. We thus ban
       1 as a sensible input and we warn about its use. Then we only have the
       2 action internally stored as TRUE. */

    if(1 == arg) {
      failf(data, "CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.proxy_ssl.primary.verifyhost = (0 != arg)?TRUE:FALSE;

    /* Update the current connection proxy_ssl_config. */
    if(data->easy_conn) {
      data->easy_conn->proxy_ssl_config.verifyhost =
        data->set.proxy_ssl.primary.verifyhost;
    }
    break;
  }
  case CURLOPT_SSL_VERIFYSTATUS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_VERIFYSTATUS", param_in);

    /*
     * Enable certificate status verifying.
     */
    if(!Curl_ssl_cert_status_request()) {
      result = CURLE_NOT_BUILT_IN;
      break;
    }

    data->set.ssl.primary.verifystatus = (0 != param_in) ?
      TRUE : FALSE;

    /* Update the current connection ssl_config. */
    if(data->easy_conn) {
      data->easy_conn->ssl_config.verifystatus =
        data->set.ssl.primary.verifystatus;
    }
    break;
  }
  case CURLOPT_SSL_CTX_FUNCTION:
  {
    curl_ssl_ctx_callback param_in = va_arg(param, curl_ssl_ctx_callback);
    debugPrintObj(data, "CURLOPT_SSL_CTX_FUNCTION", param_in);

    /*
     * Set a SSL_CTX callback
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_SSL_CTX)
      data->set.ssl.fsslctx = param_in;
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_SSL_CTX_DATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_SSL_CTX_DATA", param_in);

    /*
     * Set a SSL_CTX callback parameter pointer
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_SSL_CTX)
      data->set.ssl.fsslctxp = param_in;
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_SSL_FALSESTART:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_FALSESTART", param_in);

    /*
     * Enable TLS false start.
     */
    if(!Curl_ssl_false_start()) {
      result = CURLE_NOT_BUILT_IN;
      break;
    }

    data->set.ssl.falsestart = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_CERTINFO:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_CERTINFO", param_in);

#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_CERTINFO)
      data->set.ssl.certinfo = (0 != param_in) ? TRUE : FALSE;
    else
#endif
      result = CURLE_NOT_BUILT_IN;
        break;
  }
  case CURLOPT_PINNEDPUBLICKEY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PINNEDPUBLICKEY", param_in);

    /*
     * Set pinned public key for SSL connection.
     * Specify file name of the public key in DER format.
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_PINNEDPUBKEY)
      result = Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG],
                              param_in);
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_PROXY_PINNEDPUBLICKEY:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_PINNEDPUBLICKEY", param_in);

    /*
     * Set pinned public key for SSL connection.
     * Specify file name of the public key in DER format.
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_PINNEDPUBKEY)
      result = Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY],
                              param_in);
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_CAINFO:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_CAINFO", param_in);

    /*
     * Set CA info for SSL connection. Specify file name of the CA certificate
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CAFILE_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_CAINFO:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_CAINFO", param_in);

    /*
     * Set CA info SSL connection for proxy. Specify file name of the
     * CA certificate
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CAFILE_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_CAPATH:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_CAPATH", param_in);

    /*
     * Set CA path info for SSL connection. Specify directory name of the CA
     * certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_CA_PATH)
      /* This does not work on windows. */
      result = Curl_setstropt(&data->set.str[STRING_SSL_CAPATH_ORIG],
                              param_in);
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_PROXY_CAPATH:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_CAPATH", param_in);

    /*
     * Set CA path info for SSL connection proxy. Specify directory name of the
     * CA certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if(Curl_ssl->supports & SSLSUPP_CA_PATH)
      /* This does not work on windows. */
      result = Curl_setstropt(&data->set.str[STRING_SSL_CAPATH_PROXY],
                              param_in);
    else
#endif
      result = CURLE_NOT_BUILT_IN;
    break;
  }
  case CURLOPT_CRLFILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_CRLFILE", param_in);

    /*
     * Set CRL file info for SSL connection. Specify file name of the CRL
     * to check certificates revocation
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CRLFILE_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_PROXY_CRLFILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_CRLFILE", param_in);

    /*
     * Set CRL file info for SSL connection for proxy. Specify file name of the
     * CRL to check certificates revocation
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_CRLFILE_PROXY],
                            param_in);
    break;
  }
  case CURLOPT_ISSUERCERT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_ISSUERCERT", param_in);

    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    result = Curl_setstropt(&data->set.str[STRING_SSL_ISSUERCERT_ORIG],
                            param_in);
    break;
  }
  case CURLOPT_TELNETOPTIONS:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_TELNETOPTIONS", param_in);

    /*
     * Set a linked list of telnet options
     */
    data->set.telnet_options = param_in;
    break;
  }

  case CURLOPT_BUFFERSIZE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_BUFFERSIZE", param_in);

    /*
     * The application kindly asks for a differently sized receive buffer.
     * If it seems reasonable, we'll use it.
     */
    arg = param_in;

    if(arg > READBUFFER_MAX)
      arg = READBUFFER_MAX;
    else if(arg < 1)
      arg = READBUFFER_SIZE;
    else if(arg < READBUFFER_MIN)
      arg = READBUFFER_MIN;

    /* Resize if new size */
    if(arg != data->set.buffer_size) {
      char *newbuff = realloc(data->state.buffer, arg + 1);
      if(!newbuff) {
        DEBUGF(fprintf(stderr, "Error: realloc of buffer failed\n"));
        result = CURLE_OUT_OF_MEMORY;
      }
      else
        data->state.buffer = newbuff;
    }
    data->set.buffer_size = arg;

    break;
  }

  case CURLOPT_NOSIGNAL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NOSIGNAL", param_in);

    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    data->set.no_signal = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_SHARE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_SHARE", param_in);

  {
    struct Curl_share *set;
    set = va_arg(param, struct Curl_share *);

    /* disconnect from old share, if any */
    if(data->share) {
      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      if(data->dns.hostcachetype == HCACHE_SHARED) {
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies == data->cookies)
        data->cookies = NULL;
#endif

      if(data->share->sslsession == data->state.session)
        data->state.session = NULL;

#ifdef USE_LIBPSL
      if(data->psl == &data->share->psl)
        data->psl = data->multi? &data->multi->psl: NULL;
#endif

      data->share->dirty--;

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
      data->share = NULL;
    }

    /* use new share if it set */
    data->share = set;
    if(data->share) {

      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      data->share->dirty++;

      if(data->share->specifier & (1<< CURL_LOCK_DATA_DNS)) {
        /* use shared host cache */
        data->dns.hostcache = &data->share->hostcache;
        data->dns.hostcachetype = HCACHE_SHARED;
      }
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies) {
        /* use shared cookie list, first free own one if any */
        Curl_cookie_cleanup(data->cookies);
        /* enable cookies since we now use a share that uses cookies! */
        data->cookies = data->share->cookies;
      }
#endif   /* CURL_DISABLE_HTTP */
      if(data->share->sslsession) {
        data->set.general_ssl.max_ssl_sessions = data->share->max_ssl_sessions;
        data->state.session = data->share->sslsession;
      }
#ifdef USE_LIBPSL
      if(data->share->specifier & (1 << CURL_LOCK_DATA_PSL))
        data->psl = &data->share->psl;
#endif

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    }
    /* check for host cache not needed,
     * it will be done by curl_easy_perform */
  }
  break;
  }

  case CURLOPT_PRIVATE:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_PRIVATE", param_in);

    /*
     * Set private data pointer.
     */
    data->set.private_data = param_in;
    break;
  }

  case CURLOPT_MAXFILESIZE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_MAXFILESIZE", param_in);

    /*
     * Set the maximum size of a file to download.
     */
    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.max_filesize = arg;
    break;
  }

#ifdef USE_SSL
  case CURLOPT_USE_SSL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_USE_SSL", param_in);

    /*
     * Make transfers attempt to use SSL/TLS.
     */
    arg = param_in;
    if((arg < CURLUSESSL_NONE) || (arg > CURLUSESSL_ALL))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.use_ssl = (curl_usessl)arg;
    break;
  }

  case CURLOPT_SSL_OPTIONS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_OPTIONS", param_in);

    arg = param_in;
    data->set.ssl.enable_beast = arg&CURLSSLOPT_ALLOW_BEAST?TRUE:FALSE;
    data->set.ssl.no_revoke = !!(arg & CURLSSLOPT_NO_REVOKE);
    break;
  }

  case CURLOPT_PROXY_SSL_OPTIONS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROXY_SSL_OPTIONS", param_in);

    arg = param_in;
    data->set.proxy_ssl.enable_beast = arg&CURLSSLOPT_ALLOW_BEAST?TRUE:FALSE;
    data->set.proxy_ssl.no_revoke = !!(arg & CURLSSLOPT_NO_REVOKE);
    break;
  }

#endif
  case CURLOPT_FTPSSLAUTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_FTPSSLAUTH", param_in);

    /*
     * Set a specific auth for FTP-SSL transfers.
     */
    arg = param_in;
    if((arg < CURLFTPAUTH_DEFAULT) || (arg > CURLFTPAUTH_TLS))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.ftpsslauth = (curl_ftpauth)arg;
    break;
  }

  case CURLOPT_IPRESOLVE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_IPRESOLVE", param_in);

    arg = param_in;
    if((arg < CURL_IPRESOLVE_WHATEVER) || (arg > CURL_IPRESOLVE_V6))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.ipver = arg;
    break;
  }

  case CURLOPT_MAXFILESIZE_LARGE:
  {
    curl_off_t param_in = va_arg(param, curl_off_t);
    debugPrintOffT(data, "CURLOPT_MAXFILESIZE_LARGE", param_in);

    /*
     * Set the maximum size of a file to download.
     */
    if(param_in < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.max_filesize = param_in;
    break;
  }

  case CURLOPT_TCP_NODELAY:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TCP_NODELAY", param_in);

    /*
     * Enable or disable TCP_NODELAY, which will disable/enable the Nagle
     * algorithm
     */
    data->set.tcp_nodelay = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_ACCOUNT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_FTP_ACCOUNT", param_in);

    result = Curl_setstropt(&data->set.str[STRING_FTP_ACCOUNT],
                            param_in);
    break;
  }

  case CURLOPT_IGNORE_CONTENT_LENGTH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_IGNORE_CONTENT_LENGTH", param_in);

    data->set.ignorecl = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_CONNECT_ONLY:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_CONNECT_ONLY", param_in);

    /*
     * No data transfer, set up connection and let application use the socket
     */
    data->set.connect_only = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_FTP_ALTERNATIVE_TO_USER", param_in);

    result = Curl_setstropt(&data->set.str[STRING_FTP_ALTERNATIVE_TO_USER],
                            param_in);
    break;
  }

  case CURLOPT_SOCKOPTFUNCTION:
  {
    curl_sockopt_callback param_in = va_arg(param, curl_sockopt_callback);
    debugPrintObj(data, "CURLOPT_SOCKOPTFUNCTION", param_in);

    /*
     * socket callback function: called after socket() but before connect()
     */
    data->set.fsockopt = param_in;
    break;
  }

  case CURLOPT_SOCKOPTDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_SOCKOPTDATA", param_in);

    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.sockopt_client = param_in;
    break;
  }

  case CURLOPT_OPENSOCKETFUNCTION:
  {
    curl_opensocket_callback param_in = va_arg(param, curl_opensocket_callback);
    debugPrintObj(data, "CURLOPT_OPENSOCKETFUNCTION", param_in);

    /*
     * open/create socket callback function: called instead of socket(),
     * before connect()
     */
    data->set.fopensocket = param_in;
    break;
  }

  case CURLOPT_OPENSOCKETDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_OPENSOCKETDATA", param_in);

    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.opensocket_client = param_in;
    break;
  }

  case CURLOPT_CLOSESOCKETFUNCTION:
  {
    curl_closesocket_callback param_in = va_arg(param, curl_closesocket_callback);
    debugPrintObj(data, "CURLOPT_CLOSESOCKETFUNCTION", param_in);

    /*
     * close socket callback function: called instead of close()
     * when shutting down a connection
     */
    data->set.fclosesocket = param_in;
    break;
  }

  case CURLOPT_RESOLVER_START_FUNCTION:
  {
    curl_resolver_start_callback param_in = va_arg(param, curl_resolver_start_callback);
    debugPrintObj(data, "CURLOPT_RESOLVER_START_FUNCTION", param_in);

    /*
     * resolver start callback function: called before a new resolver request
     * is started
     */
    data->set.resolver_start = param_in;
    break;
  }

  case CURLOPT_RESOLVER_START_DATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_RESOLVER_START_DATA", param_in);

    /*
     * resolver start callback data pointer. Might be NULL.
     */
    data->set.resolver_start_client = param_in;
    break;
  }

  case CURLOPT_CLOSESOCKETDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_CLOSESOCKETDATA", param_in);

    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.closesocket_client = param_in;
    break;
  }

  case CURLOPT_SSL_SESSIONID_CACHE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_SESSIONID_CACHE", param_in);

    data->set.ssl.primary.sessionid = (0 != param_in) ?
      TRUE : FALSE;
    data->set.proxy_ssl.primary.sessionid = data->set.ssl.primary.sessionid;
    break;
  }

#if defined(USE_LIBSSH2) || defined(USE_LIBSSH)
    /* we only include SSH options if explicitly built to support SSH */
  case CURLOPT_SSH_AUTH_TYPES:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSH_AUTH_TYPES", param_in);

    data->set.ssh_auth_types = param_in;
    break;
  }

  case CURLOPT_SSH_PUBLIC_KEYFILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSH_PUBLIC_KEYFILE", param_in);

    /*
     * Use this file instead of the $HOME/.ssh/id_dsa.pub file
     */
    result = Curl_setstropt(&data->set.str[STRING_SSH_PUBLIC_KEY],
                            param_in);
    break;
  }

  case CURLOPT_SSH_PRIVATE_KEYFILE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSH_PRIVATE_KEYFILE", param_in);

    /*
     * Use this file instead of the $HOME/.ssh/id_dsa file
     */
    result = Curl_setstropt(&data->set.str[STRING_SSH_PRIVATE_KEY],
                            param_in);
    break;
  }
  case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSH_HOST_PUBLIC_KEY_MD5", param_in);

    /*
     * Option to allow for the MD5 of the host public key to be checked
     * for validation purposes.
     */
    result = Curl_setstropt(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5],
                            param_in);
    break;
  }
#ifdef HAVE_LIBSSH2_KNOWNHOST_API
  case CURLOPT_SSH_KNOWNHOSTS:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_SSH_KNOWNHOSTS", param_in);

    /*
     * Store the file name to read known hosts from.
     */
    result = Curl_setstropt(&data->set.str[STRING_SSH_KNOWNHOSTS],
                            param_in);
    break;
  }

  case CURLOPT_SSH_KEYFUNCTION:
  {
    curl_sshkeycallback param_in = va_arg(param, curl_sshkeycallback);
    debugPrintObj(data, "CURLOPT_SSH_KEYFUNCTION", param_in);

    /* setting to NULL is fine since the ssh.c functions themselves will
       then rever to use the internal default */
    data->set.ssh_keyfunc = param_in;
    break;
  }

  case CURLOPT_SSH_KEYDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_SSH_KEYDATA", param_in);

    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    data->set.ssh_keyfunc_userp = param_in;
    break;
  }
#endif /* HAVE_LIBSSH2_KNOWNHOST_API */
#endif /* USE_LIBSSH2 */

  case CURLOPT_HTTP_TRANSFER_DECODING:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTP_TRANSFER_DECODING", param_in);

    /*
     * disable libcurl transfer encoding is used
     */
    data->set.http_te_skip = (0 == param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_HTTP_CONTENT_DECODING:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HTTP_CONTENT_DECODING", param_in);

    /*
     * raw data passed to the application when content encoding is used
     */
    data->set.http_ce_skip = (0 == param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_NEW_FILE_PERMS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NEW_FILE_PERMS", param_in);

    /*
     * Uses these permissions instead of 0644
     */
    arg = param_in;
    if((arg < 0) || (arg > 0777))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.new_file_perms = arg;
    break;
  }

  case CURLOPT_NEW_DIRECTORY_PERMS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_NEW_DIRECTORY_PERMS", param_in);

    /*
     * Uses these permissions instead of 0755
     */
    arg = param_in;
    if((arg < 0) || (arg > 0777))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.new_directory_perms = arg;
    break;
  }

  case CURLOPT_ADDRESS_SCOPE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_ADDRESS_SCOPE", param_in);

    /*
     * We always get longs when passed plain numericals, but for this value we
     * know that an unsigned int will always hold the value so we blindly
     * typecast to this type
     */
    arg = param_in;
    if((arg < 0) || (arg > 0xf))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.scope_id = curlx_sltoui(arg);
    break;
  }

  case CURLOPT_PROTOCOLS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PROTOCOLS", param_in);

    /* set the bitmask for the protocols that are allowed to be used for the
       transfer, which thus helps the app which takes URLs from users or other
       external inputs and want to restrict what protocol(s) to deal
       with. Defaults to CURLPROTO_ALL. */
    data->set.allowed_protocols = param_in;
    break;
  }

  case CURLOPT_REDIR_PROTOCOLS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_REDIR_PROTOCOLS", param_in);

    /* set the bitmask for the protocols that libcurl is allowed to follow to,
       as a subset of the CURLOPT_PROTOCOLS ones. That means the protocol needs
       to be set in both bitmasks to be allowed to get redirected to. Defaults
       to all protocols except FILE and SCP. */
    data->set.redir_protocols = param_in;
    break;
  }

  case CURLOPT_DEFAULT_PROTOCOL:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_DEFAULT_PROTOCOL", param_in);

    /* Set the protocol to use when the URL doesn't include any protocol */
    result = Curl_setstropt(&data->set.str[STRING_DEFAULT_PROTOCOL],
                            param_in);
    break;
  }

  case CURLOPT_MAIL_FROM:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_MAIL_FROM", param_in);

    /* Set the SMTP mail originator */
    result = Curl_setstropt(&data->set.str[STRING_MAIL_FROM],
                            param_in);
    break;
  }

  case CURLOPT_MAIL_AUTH:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_MAIL_AUTH", param_in);

    /* Set the SMTP auth originator */
    result = Curl_setstropt(&data->set.str[STRING_MAIL_AUTH],
                            param_in);
    break;
  }

  case CURLOPT_MAIL_RCPT:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_MAIL_RCPT", param_in);

    /* Set the list of mail recipients */
    data->set.mail_rcpt = param_in;
    break;
  }

  case CURLOPT_SASL_IR:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SASL_IR", param_in);

    /* Enable/disable SASL initial response */
    data->set.sasl_ir = (0 != param_in) ? TRUE : FALSE;
    break;
  }

  case CURLOPT_RTSP_REQUEST:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_RTSP_REQUEST", param_in);

    /*
     * Set the RTSP request method (OPTIONS, SETUP, PLAY, etc...)
     * Would this be better if the RTSPREQ_* were just moved into here?
     */
    long curl_rtspreq = param_in;
    Curl_RtspReq rtspreq = RTSPREQ_NONE;
    switch(curl_rtspreq) {
    case CURL_RTSPREQ_OPTIONS:
      rtspreq = RTSPREQ_OPTIONS;
      break;
    case CURL_RTSPREQ_DESCRIBE:
      rtspreq = RTSPREQ_DESCRIBE;
      break;
    case CURL_RTSPREQ_ANNOUNCE:
      rtspreq = RTSPREQ_ANNOUNCE;
      break;
    case CURL_RTSPREQ_SETUP:
      rtspreq = RTSPREQ_SETUP;
      break;
    case CURL_RTSPREQ_PLAY:
      rtspreq = RTSPREQ_PLAY;
      break;
    case CURL_RTSPREQ_PAUSE:
      rtspreq = RTSPREQ_PAUSE;
      break;
    case CURL_RTSPREQ_TEARDOWN:
      rtspreq = RTSPREQ_TEARDOWN;
      break;
     case CURL_RTSPREQ_GET_PARAMETER:
      rtspreq = RTSPREQ_GET_PARAMETER;
      break;
    case CURL_RTSPREQ_SET_PARAMETER:
      rtspreq = RTSPREQ_SET_PARAMETER;
      break;
    case CURL_RTSPREQ_RECORD:
      rtspreq = RTSPREQ_RECORD;
      break;
    case CURL_RTSPREQ_RECEIVE:
      rtspreq = RTSPREQ_RECEIVE;
      break;
    default:
      rtspreq = RTSPREQ_NONE;
    }

    data->set.rtspreq = rtspreq;
    break;
  }


  case CURLOPT_RTSP_SESSION_ID:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_RTSP_SESSION_ID", param_in);

    /*
     * Set the RTSP Session ID manually. Useful if the application is
     * resuming a previously established RTSP session
     */
    result = Curl_setstropt(&data->set.str[STRING_RTSP_SESSION_ID],
                            param_in);
    break;
  }

  case CURLOPT_RTSP_STREAM_URI:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_RTSP_STREAM_URI", param_in);

    /*
     * Set the Stream URI for the RTSP request. Unless the request is
     * for generic server options, the application will need to set this.
     */
    result = Curl_setstropt(&data->set.str[STRING_RTSP_STREAM_URI],
                            param_in);
    break;
  }

  case CURLOPT_RTSP_TRANSPORT:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_RTSP_TRANSPORT", param_in);

    /*
     * The content of the Transport: header for the RTSP request
     */
    result = Curl_setstropt(&data->set.str[STRING_RTSP_TRANSPORT],
                            param_in);
    break;
  }

  case CURLOPT_RTSP_CLIENT_CSEQ:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_RTSP_CLIENT_CSEQ", param_in);

    /*
     * Set the CSEQ number to issue for the next RTSP request. Useful if the
     * application is resuming a previously broken connection. The CSEQ
     * will increment from this new number henceforth.
     */
    data->state.rtsp_next_client_CSeq = param_in;
    break;
  }

  case CURLOPT_RTSP_SERVER_CSEQ:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_RTSP_SERVER_CSEQ", param_in);

    /* Same as the above, but for server-initiated requests */
    data->state.rtsp_next_client_CSeq = param_in;
    break;
  }

  case CURLOPT_INTERLEAVEDATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_INTERLEAVEDATA", param_in);

    data->set.rtp_out = param_in;
    break;
  }
  case CURLOPT_INTERLEAVEFUNCTION:
  {
    curl_write_callback param_in = va_arg(param, curl_write_callback);
    debugPrintObj(data, "CURLOPT_INTERLEAVEFUNCTION", param_in);

    /* Set the user defined RTP write function */
    data->set.fwrite_rtp = param_in;
    break;
  }

  case CURLOPT_WILDCARDMATCH:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_WILDCARDMATCH", param_in);

    data->set.wildcard_enabled = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_CHUNK_BGN_FUNCTION:
  {
    curl_chunk_bgn_callback param_in = va_arg(param, curl_chunk_bgn_callback);
    debugPrintObj(data, "CURLOPT_CHUNK_BGN_FUNCTION", param_in);

    data->set.chunk_bgn = param_in;
    break;
  }
  case CURLOPT_CHUNK_END_FUNCTION:
  {
    curl_chunk_end_callback param_in = va_arg(param, curl_chunk_end_callback);
    debugPrintObj(data, "CURLOPT_CHUNK_END_FUNCTION", param_in);

    data->set.chunk_end = param_in;
    break;
  }
  case CURLOPT_FNMATCH_FUNCTION:
  {
    curl_fnmatch_callback param_in = va_arg(param, curl_fnmatch_callback);
    debugPrintObj(data, "CURLOPT_FNMATCH_FUNCTION", param_in);

    data->set.fnmatch = param_in;
    break;
  }
  case CURLOPT_CHUNK_DATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_CHUNK_DATA", param_in);

    data->wildcard.customptr = param_in;
    break;
  }
  case CURLOPT_FNMATCH_DATA:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_FNMATCH_DATA", param_in);

    data->set.fnmatch_data = param_in;
    break;
  }
#ifdef USE_TLS_SRP
  case CURLOPT_TLSAUTH_USERNAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_TLSAUTH_USERNAME", param_in);

    result = Curl_setstropt(&data->set.str[STRING_TLSAUTH_USERNAME_ORIG],
                            param_in);
    if(data->set.str[STRING_TLSAUTH_USERNAME_ORIG] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  }
  case CURLOPT_PROXY_TLSAUTH_USERNAME:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_TLSAUTH_USERNAME", param_in);

    result = Curl_setstropt(&data->set.str[STRING_TLSAUTH_USERNAME_PROXY],
                            param_in);
    if(data->set.str[STRING_TLSAUTH_USERNAME_PROXY] &&
       !data->set.proxy_ssl.authtype)
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  }
  case CURLOPT_TLSAUTH_PASSWORD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_TLSAUTH_PASSWORD", param_in);

    result = Curl_setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD_ORIG],
                            param_in);
    if(data->set.str[STRING_TLSAUTH_USERNAME_ORIG] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  }
  case CURLOPT_PROXY_TLSAUTH_PASSWORD:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_TLSAUTH_PASSWORD", param_in);

    result = Curl_setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD_PROXY],
                            param_in);
    if(data->set.str[STRING_TLSAUTH_USERNAME_PROXY] &&
       !data->set.proxy_ssl.authtype)
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  }
  case CURLOPT_TLSAUTH_TYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_TLSAUTH_TYPE", param_in);

    argptr = param_in;
    if(!argptr ||
       strncasecompare(argptr, "SRP", strlen("SRP")))
      data->set.ssl.authtype = CURL_TLSAUTH_SRP;
    else
      data->set.ssl.authtype = CURL_TLSAUTH_NONE;
    break;
  }
  case CURLOPT_PROXY_TLSAUTH_TYPE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_PROXY_TLSAUTH_TYPE", param_in);

    argptr = param_in;
    if(!argptr ||
       strncasecompare(argptr, "SRP", strlen("SRP")))
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP;
    else
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_NONE;
    break;
  }
#endif
  case CURLOPT_DNS_SERVERS:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_DNS_SERVERS", param_in);

    result = Curl_set_dns_servers(data, param_in);
    break;
  }
  case CURLOPT_DNS_INTERFACE:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_DNS_INTERFACE", param_in);

    result = Curl_set_dns_interface(data, param_in);
    break;
  }
  case CURLOPT_DNS_LOCAL_IP4:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_DNS_LOCAL_IP4", param_in);

    result = Curl_set_dns_local_ip4(data, param_in);
    break;
  }
  case CURLOPT_DNS_LOCAL_IP6:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_DNS_LOCAL_IP6", param_in);

    result = Curl_set_dns_local_ip6(data, param_in);
    break;
  }

  case CURLOPT_TCP_KEEPALIVE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TCP_KEEPALIVE", param_in);

    data->set.tcp_keepalive = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_TCP_KEEPIDLE:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TCP_KEEPIDLE", param_in);

    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.tcp_keepidle = arg;
    break;
  }
  case CURLOPT_TCP_KEEPINTVL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TCP_KEEPINTVL", param_in);

    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.tcp_keepintvl = arg;
    break;
  }
  case CURLOPT_TCP_FASTOPEN:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_TCP_FASTOPEN", param_in);

#if defined(CONNECT_DATA_IDEMPOTENT) || defined(MSG_FASTOPEN) || \
   defined(TCP_FASTOPEN_CONNECT)
    data->set.tcp_fastopen = (0 != param_in)?TRUE:FALSE;
#else
    result = CURLE_NOT_BUILT_IN;
#endif
    break;
  }
  case CURLOPT_SSL_ENABLE_NPN:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_ENABLE_NPN", param_in);

    data->set.ssl_enable_npn = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_SSL_ENABLE_ALPN:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSL_ENABLE_ALPN", param_in);

    data->set.ssl_enable_alpn = (0 != param_in) ? TRUE : FALSE;
    break;
  }

#ifdef USE_UNIX_SOCKETS
  case CURLOPT_UNIX_SOCKET_PATH:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_UNIX_SOCKET_PATH", param_in);

    data->set.abstract_unix_socket = FALSE;
    result = Curl_setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH],
                            param_in);
    break;
  }
  case CURLOPT_ABSTRACT_UNIX_SOCKET:
  {
    char* param_in = va_arg(param, char*);
    debugPrintStr(data, "CURLOPT_ABSTRACT_UNIX_SOCKET", param_in);

    data->set.abstract_unix_socket = TRUE;
    result = Curl_setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH],
                            param_in);
    break;
  }
#endif

  case CURLOPT_PATH_AS_IS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PATH_AS_IS", param_in);

    data->set.path_as_is = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_PIPEWAIT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_PIPEWAIT", param_in);

    data->set.pipewait = (0 != param_in) ? TRUE : FALSE;
    break;
  }
  case CURLOPT_STREAM_WEIGHT:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_STREAM_WEIGHT", param_in);

#ifndef USE_NGHTTP2
    return CURLE_NOT_BUILT_IN;
#else
    if((param_in >= 1) && (param_in <= 256))
      data->set.stream_weight = (int)param_in;
    break;
#endif
  }
  case CURLOPT_STREAM_DEPENDS:
  case CURLOPT_STREAM_DEPENDS_E:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_STREAM_DEPENDS", param_in);
    debugPrintObj(data, "CURLOPT_STREAM_DEPENDS_E", param_in);

#ifndef USE_NGHTTP2
    return CURLE_NOT_BUILT_IN;
#else
    struct Curl_easy *dep = va_arg(param, struct Curl_easy *);
    if(!dep || GOOD_EASY_HANDLE(dep)) {
      if(data->set.stream_depends_on) {
        Curl_http2_remove_child(data->set.stream_depends_on, data);
      }
      Curl_http2_add_child(dep, data, (option == CURLOPT_STREAM_DEPENDS_E));
    }
    break;
#endif
  }
  case CURLOPT_CONNECT_TO:
  {
    void* param_in = va_arg(param, void*);
    debugPrintObj(data, "CURLOPT_CONNECT_TO", param_in);

    data->set.connect_to = param_in;
    break;
  }
  case CURLOPT_SUPPRESS_CONNECT_HEADERS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SUPPRESS_CONNECT_HEADERS", param_in);

    data->set.suppress_connect_headers = (0 != param_in)?TRUE:FALSE;
    break;
  }
  case CURLOPT_SSH_COMPRESSION:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_SSH_COMPRESSION", param_in);

    data->set.ssh_compression = (0 != param_in)?TRUE:FALSE;
    break;
  }
  case CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS", param_in);

    arg = param_in;
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    data->set.happy_eyeballs_timeout = arg;
    break;
  }
  case CURLOPT_DNS_SHUFFLE_ADDRESSES:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_DNS_SHUFFLE_ADDRESSES", param_in);

    data->set.dns_shuffle_addresses = (0 != param_in) ? TRUE:FALSE;
    break;
  }
  case CURLOPT_DISALLOW_USERNAME_IN_URL:
  {
    long param_in = va_arg(param, long);
    debugPrintLong(data, "CURLOPT_DISALLOW_USERNAME_IN_URL", param_in);

    data->set.disallow_username_in_url =
      (0 != param_in) ? TRUE : FALSE;
    break;
  }
  default:
    /* unknown tag and its companion, just ignore: */
    result = CURLE_UNKNOWN_OPTION;
    break;
  }

  return result;
}

/*
 * curl_easy_setopt() is the external interface for setting options on an
 * easy handle.
 *
 * NOTE: This is one of few API functions that are allowed to be called from
 * within a callback.
 */

#undef curl_easy_setopt
CURLcode curl_easy_setopt(struct Curl_easy *data, CURLoption tag, ...)
{
  va_list arg;
  CURLcode result;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  result = Curl_vsetopt(data, tag, arg);

  va_end(arg);
  return result;
}
