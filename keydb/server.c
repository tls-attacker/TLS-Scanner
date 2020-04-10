/**
 *      @file    server.c
 *      @version $Format:%h%d$
 *
 *      Simple non-blocking MatrixSSL server example for multiple connections.
 *      Uses a single, hardcoded RSA identity.  No client authentication.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#ifndef NEED_PS_TIME_CONCRETE
# define NEED_PS_TIME_CONCRETE
#endif

#include "app.h"
#include "matrixssl/matrixsslApi.h"
#include "core/psUtil.h"
#include "osdep_sys_socket.h"
#include "osdep_sys_types.h"
#include "osdep_sys_time.h"

# ifdef MATRIX_USE_FILE_SYSTEM
#  ifdef USE_SERVER_SIDE_SSL

#  include "osdep_signal.h"                /* Defines SIGTERM, etc. */

#  ifndef MATRIX_TESTING_ENVIRONMENT /* Omit the message when testing. */
#   define WARNING_MESSAGE "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#   define WARNING_MESSAGE_DEFAULT_KEY
#   include "pscompilerwarning.h"
#  endif /* MATRIX_TESTING_ENVIRONMENT */

#  define ALLOW_ANON_CONNECTIONS  1
#  define SEND_CLOSURE_ALERT

/* Default keys and certs if nothing provided on command line */
const char *key_dir;
const char *testkeys_root = "testkeys";
const char *testkeys_apps_ssl = "../../testkeys";
const static char g_defaultCertFile[] = "RSA/2048_RSA.pem";
const static char g_defaultPrivkeyFile[] = "RSA/2048_RSA_KEY.pem";
const static char g_defaultCAFile[] = "RSA/2048_RSA_CA.pem";

#  ifdef USE_TLS_1_3
#   include "testkeys/PSK/tls13_psk.h"
#  endif /* USE_TLS_1_3 */

static int g_use_psk;

#  ifdef USE_OCSP_RESPONSE
static int g_test_ocsp_stapling_good;
static int g_test_ocsp_stapling_revoked;
#  endif

#  ifdef REQUIRE_DH_PARAMS
const static char g_defaultDHParamFile[] = "DH/2048_DH_PARAMS.pem";
#  endif

#  ifdef USE_REHANDSHAKING
static int g_doSelfInitiatedRehandshakeTest;
static int g_numRehandshakes;
static int g_maxRehandshakes;
#  endif

/*
        Require client authentication?
        Use --require-client-auth command line argument to enable.
*/
static int g_require_client_auth;

/********************************** Defines ***********************************/

#  define SSL_TIMEOUT         45000 /* In milliseconds */
#  define SELECT_TIME         1000  /* In milliseconds */
#  define RESPONSE_REC_LEN    SSL_MAX_PLAINTEXT_LEN

#  define GOTO_SANITY         32/* Must be <= 255 */
/*
    The ACCEPT_QUEUE is an optimization mechanism that allows the server to
    accept() up to this many connections before serving any of them.  The
    reason is that the timeout waiting for the accept() is much shorter
    than the timeout for the actual processing.
 */
#   define ACCEPT_QUEUE        16

/********************************** Globals ***********************************/

static DLListEntry g_conns;
static int32 g_exitFlag;
static int g_port;
static psProtocolVersion_t g_min_version;
static psProtocolVersion_t g_max_version;
static int g_use_default_versions;
static int g_disabledCiphers;
static uint16_t g_disabledCipher[SSL_MAX_DISABLED_CIPHERS];
static psList_t *g_groupList;
static psList_t *g_sigAlgsList;
static psList_t *g_sigAlgsCertList;
static psList_t *g_supportedVersionsList;
static int g_max_early_data;
static long int g_tls13_block_size;
static int g_allow_out_of_date_cert_chain;

#  define MAX_KEYFILE_PATH    256
#  define MAX_SERVER_NAME     256
#  define MAX_PASSWORD_LEN    MAX_KEYFILE_PATH

static char g_keyfilePath[MAX_KEYFILE_PATH];
static char g_privkeyFile[MAX_KEYFILE_PATH];
static char g_serverName[MAX_SERVER_NAME];
static char g_identityCert[MAX_KEYFILE_PATH];
static char g_dhParamFile[MAX_KEYFILE_PATH];
static char g_caFile[MAX_KEYFILE_PATH];
static char g_password[MAX_PASSWORD_LEN];

static unsigned char g_httpResponseHdr[] = "HTTP/1.0 200 OK\r\n"
                                           "Server: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
                                           "Pragma: no-cache\r\n"
                                           "Cache-Control: no-cache\r\n"
                                           "Content-type: text/plain\r\n"
                                           "Content-length: 9\r\n"
                                           "\r\n"
                                           "MatrixSSL";
#  ifdef USE_TLS_1_3
static const char *g_httpResponseHeaderTls13 = "HTTP/1.1 200 OK\r\n"
                                           "Server: MatrixSSL " MATRIXSSL_VERSION "\r\n"
                                           "Connection: close\r\n"
                                           "Cache-Control: no-cache\r\n"
                                           "Content-Type: text/html; charset=UTF-8\r\n"
                                           "Content-Length: 187\r\n"
                                           "\r\n\r\n"
                                           "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                                           "<html>\n"
                                           " <head>\n"
                                           "  <title>Connected to MatrixSSL Server</title>\n"
                                           " </head>\n"
                                           "<body>\n"
                                           " <h1>MatrixSSL now supports TLS 1.3</h1>\n"
                                           "</body>\n"
                                           "</html>\n";
#  endif
#  ifdef USE_STATELESS_SESSION_TICKETS
static int32 sessTicketCb(void *keys, unsigned char name[16], short found);
static unsigned char sessTicketSymKey[32] = { 0 };
static unsigned char sessTicketMacKey[32] = { 0 };
#  endif

/****************************** Local Functions *******************************/

static int32 selectLoop(sslKeys_t *keys, SOCKET lfd);
static int32 httpWriteResponse(httpConn_t *conn);
static int setSocketOptions(SOCKET fd);
static SOCKET lsocketListen(short port, int32 *err);
static void closeConn(httpConn_t *cp, int32 reason);
# ifdef USE_TLS_1_3
static int32_t sendHtmlResponseTls13(ssl_t *ssl);
# endif
static int32_t sendHtmlResponse(ssl_t *ssl);

#  ifdef POSIX
static void sigsegv_handler(int i);
static void sigintterm_handler(int i);
static int32 sighandlers(void);
#  endif /* POSIX */

#  ifdef MATRIX_USE_FILE_SYSTEM
/* Check whether we are in the root directory of MatrixSSL.
   Used to determine paths of default certificates and keys. */
static psBool_t cwdIsMatrixRoot(void)
{
    psRes_t rc;
    unsigned char *buf;
    psSizeL_t len;

    rc = psGetFileBuf(NULL, "testkeys/RSA/2048_RSA_KEY.pem", &buf, &len);
    if (rc != PS_SUCCESS)
    {
        return PS_FALSE;
    }

    psFree(buf, NULL);
    return PS_TRUE;
}
#  endif

/************************ Handshake Callback Functions ************************/
/* A server will make use of a certificate callback if client authentication
    is being used.  This callback will be invoked during the handshake to
    allow application level inspection of the client certificate and halt
    the connection if required.  See the documentation for more information
    on the Certificte Callback function */
int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
    return alert;
}


#  ifdef USE_STATELESS_SESSION_TICKETS
/* This callback will be invoked each time a client sends a session ticket and
    can be used as an opportunity for the application to locate and load the
    correct key or to void the ticket and revert to a full handshake. See
    the API documenation for matrixSslSetSessionTicketCallback for more info */
int32 sessTicketCb(void *keys, unsigned char name[16], short found)
{
    if (found)
    {
        /* Was already cached */
        return PS_SUCCESS;
    }
    /* Example.  If name was located, different keys would be loaded this way. Of course here
       we are loading the same keys already loaded. */
    return matrixSslLoadSessionTicketKeys((sslKeys_t *) keys, name,
        sessTicketSymKey, sizeof(sessTicketSymKey),
        sessTicketMacKey, sizeof(sessTicketMacKey));
}
#  endif

void SNIcallback(void *ssl, char *hostname, int32 hostnameLen,
    sslKeys_t **newKeys)
{
    ssl_t *lssl = (ssl_t *)ssl;
    char *str = Malloc(hostnameLen + 1);
    psSize_t expectedLen;

    Memcpy(str, hostname, hostnameLen);
    str[hostnameLen] = '\0';
    Printf("Hostname in ClientHello SNI extension: %s\n", str);

    expectedLen = Strlen(g_serverName);

    if (expectedLen != 0 &&
            (hostnameLen != expectedLen ||
                    Memcmp(hostname, g_serverName, hostnameLen)))
    {
        Printf("Received unrecognized server name in the SNI extension\n");
        *newKeys = NULL;
    }
    else
    {
        *newKeys = matrixSslGetKeys(lssl);
    }

    Free(str);
}

int32 setProtocolVersions(sslSessOpts_t *options)
{
    psList_t *supportedVersion;
    psProtocolVersion_t supportedVersions[TLS_MAX_SUPPORTED_VERSIONS] = {0};
    psSize_t i;
    int32 rc;

    if (g_supportedVersionsList)
    {
        supportedVersion = g_supportedVersionsList;
        i = 0;
        while (supportedVersion)
        {
            supportedVersions[i] = atoi((char* )supportedVersion->item);
            supportedVersions[i] = matrixSslVersionFromMinorDigit(
                    supportedVersions[i]);
            supportedVersion = supportedVersion->next;
            i++;
        }
        rc = matrixSslSessOptsSetServerTlsVersions(options,
                supportedVersions,
                i);
    }
    else
    {
        rc = matrixSslSessOptsSetServerTlsVersionRange(options,
                g_min_version,
                g_max_version);
    }
    return rc;
}

/******************************************************************************/
/**
    Display connections per second (if more than 0), at most once per second
 */
static uint64_t g_handshakes = 0;
static void displayStats(void)
{
    static uint64_t s_handshakes = 0;   /* last value displayed */
    static psTimeSeconds_t s_t = (psTimeSeconds_t) 0;     /* last time displayed */
    psTimeSeconds_t t;

    if (g_handshakes > s_handshakes)
    {
        t = psGetEpochTime();
        if (t > s_t)
        {
            Printf("%u CPS\n",
                (uint32_t) (g_handshakes - s_handshakes) / (uint32_t) (t - s_t));
            s_handshakes = g_handshakes;
            s_t = t;
        }
    }
}

/******************************************************************************/
/*
    Non-blocking socket event handler
    Wait one time in select for events on any socket
    This will accept new connections, read and write to sockets that are
    connected, and close sockets as required.
 */
static int32 selectLoop(sslKeys_t *keys, SOCKET lfd)
{
    httpConn_t *cp;
    psTime_t now;
    DLListEntry connsTmp;
    DLListEntry *pList;

    fd_set readfd, writefd;
    struct timeval timeout;
    SOCKET fd, maxfd;

    unsigned char *buf;
    int32 rc, len, transferred, val, specialAppData;
    unsigned char rSanity, wSanity, acceptSanity;
    psList_t *sigAlg;
    uint16_t sigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS] = {0};

    sslSessOpts_t options;
    psSize_t i;
# ifdef USE_TLS_1_3
    psSize_t groupsLen;
    psList_t *group;
    uint16_t groups[TLS_1_3_MAX_GROUPS] = {0};
# endif

    DLListInit(&connsTmp);
    rc = PS_SUCCESS;
    maxfd = INVALID_SOCKET;
    timeout.tv_sec = SELECT_TIME / 1000;
    timeout.tv_usec = (SELECT_TIME % 1000) * 1000;
    FD_ZERO(&readfd);
    FD_ZERO(&writefd);

    /* Always set readfd for listening socket */
    FD_SET(lfd, &readfd);
    if (lfd > maxfd)
    {
        maxfd = lfd;
    }
/*
    Check timeouts and set readfd and writefd for connections as required.
    We use connsTemp so that removal on error from the active iteration list
        doesn't interfere with list traversal
 */
    psGetTime(&now, NULL);
    while (!DLListIsEmpty(&g_conns))
    {
        pList = DLListGetHead(&g_conns);
        cp = DLListGetContainer(pList, httpConn_t, List);
        DLListInsertTail(&connsTmp, &cp->List);
        /*      If timeout != 0 msec ith no new data, close */
        if (cp->timeout && (psDiffMsecs(cp->time, now, NULL) >
                            (int32) cp->timeout))
        {
            closeConn(cp, PS_TIMEOUT_FAIL);
            continue;   /* Next connection */
        }
        /* Always select for read */
        FD_SET(cp->fd, &readfd);
        /* Select for write if there's pending write data or connection */
        if (matrixSslGetOutdata(cp->ssl, NULL) > 0)
        {
            FD_SET(cp->fd, &writefd);
        }
        /* Housekeeping for maxsock in select call */
        if (cp->fd > maxfd)
        {
            maxfd = cp->fd;
        }
    }

    /* Use select to check for events on the sockets */
    if ((val = Select(maxfd + 1, &readfd, &writefd, NULL, &timeout)) <= 0)
    {
        /* On error, restore global connections list */
        while (!DLListIsEmpty(&connsTmp))
        {
            pList = DLListGetHead(&connsTmp);
            cp = DLListGetContainer(pList, httpConn_t, List);
            DLListInsertTail(&g_conns, &cp->List);
        }
        /* Select timeout */
        if (val == 0)
        {
            return PS_TIMEOUT_FAIL;
        }
        /* Woke due to interrupt */
        if (SOCKET_ERRNO == EINTR)
        {
            return PS_TIMEOUT_FAIL;
        }
        /* Should attempt to handle more errnos, such as EBADF */
        return PS_PLATFORM_FAIL;
    }

    /* Check listener for new incoming socket connections */
    if (FD_ISSET(lfd, &readfd))
    {
        for (acceptSanity = 0; acceptSanity < ACCEPT_QUEUE; acceptSanity++)
        {
            fd = accept(lfd, NULL, NULL);
            if (fd == INVALID_SOCKET)
            {
                break;  /* Nothing more to accept; next listener */
            }
            if (setSocketOptions(fd) < 0)
            {
                close(fd);
                return PS_PLATFORM_FAIL;
            }
            cp = (httpConn_t *)Malloc(sizeof(httpConn_t));
            if (cp == NULL)
            {
                close(fd);
                return PS_MEM_FAIL;
            }
            Memset(cp, 0x0, sizeof(httpConn_t));

            Memset(&options, 0x0, sizeof(sslSessOpts_t));
            options.userPtr = keys;
            /* options.extendedMasterSecret = 1; / * Require * / */
            if (g_use_default_versions == 0 &&
                setProtocolVersions(&options) < 0)
            {
                Printf("setProtocolVersions failed\n");
                close(fd);
                return PS_ARG_FAIL;
            }
# ifdef USE_TLS_1_3
            options.tls13SessionMaxEarlyData = g_max_early_data;

            /* Determine which groups to use. */
            if (g_groupList != 0)
            {
                group = g_groupList;
                i = groupsLen = 0;
                while (group)
                {
                    groups[i] = psGetNamedGroupId((const char*)group->item);
                    group = group->next;
                    groupsLen++;
                    i++;
                }
                rc = matrixSslSessOptsSetKeyExGroups(&options,
                        groups,
                        groupsLen,
                        1);
                if (rc < 0)
                {
                    Printf("matrixSslSessOptsSetKeyExGroups failed\n");
                    close(fd);
                    return rc;
                }
            }
            if (g_sigAlgsCertList != 0)
            {
                sigAlg = g_sigAlgsCertList;
                i = 0;
                while (sigAlg)
                {
                    sigAlgs[i] = psGetNamedSigAlgId((const char*)sigAlg->item);
                    sigAlg = sigAlg->next;
                    i++;
                }
                rc = matrixSslSessOptsSetSigAlgsCert(&options,
                        sigAlgs,
                        i);
                if (rc < 0)
                {
                    Printf("matrixSslSessOptsSetSigAlgsCert failed\n");
                    close(fd);
                    return rc;
                }
            }
# endif /* USE_TLS_1_3 */
            if (g_sigAlgsList != 0)
            {
                sigAlg = g_sigAlgsList;
                i = 0;
                while (sigAlg)
                {
                    sigAlgs[i] = psGetNamedSigAlgId((const char*)sigAlg->item);
                    if (sigAlgs[i] == 0)
                    {
                        Printf("Invalid signature algorithm parameter\n");
                        close(fd);
                        return PS_ARG_FAIL;
                    }
                    sigAlg = sigAlg->next;
                    i++;
                }
                rc = matrixSslSessOptsSetSigAlgs(&options,
                        sigAlgs,
                        i);
                if (rc < 0)
                {
                    Printf("matrixSslSessOptsSetSigAlgs failed\n");
                    close(fd);
                    return rc;
                }
            }

            if (g_require_client_auth)
            {
                if ((rc = matrixSslNewServerSession(&cp->ssl, keys, certCb,
                                        &options)) < 0)
                {
                    close(fd);
                    continue;
                }
            }
            else
            {
                if ((rc = matrixSslNewServerSession(&cp->ssl, keys, NULL,
                                        &options)) < 0)
                {
                    close(fd);
                    continue;
                }
            }
# ifdef USE_TLS_1_3
            if (g_tls13_block_size != 0)
            {
                rc = matrixSslSetTls13BlockPadding(cp->ssl, g_tls13_block_size);
                if (rc != PS_SUCCESS)
                {
                    close(fd);
                    continue;
                }
            }
# endif
            matrixSslRegisterSNICallback(cp->ssl, SNIcallback);
            cp->fd = fd;
            cp->timeout = SSL_TIMEOUT;
            psGetTime(&cp->time, NULL);
            cp->parsebuf = NULL;
            cp->parsebuflen = 0;
            DLListInsertTail(&connsTmp, &cp->List);
            /* Fake that there is read data available, no harm if there isn't */
            FD_SET(cp->fd, &readfd);
/*                      psTraceInt("=== New Client %d ===\n", cp->fd); */
        }
    }

    /* Check each connection for read/write activity */
    while (!DLListIsEmpty(&connsTmp))
    {
        pList = DLListGetHead(&connsTmp);
        cp = DLListGetContainer(pList, httpConn_t, List);
        DLListInsertTail(&g_conns, &cp->List);

        rSanity = wSanity = 0;
/*
        See if there's pending data to send on this connection
        We could use FD_ISSET, but this is more reliable for the current
            state of data to send.
 */
WRITE_MORE:
        if ((len = matrixSslGetOutdata(cp->ssl, &buf)) > 0)
        {
            /* Could get a EWOULDBLOCK since we don't check FD_ISSET */
            transferred = (int32) send(cp->fd, buf, len, MSG_DONTWAIT);
            /*psTraceBytes("++ sent", buf, transferred);*/
            if (transferred <= 0)
            {
#  ifdef WIN32
                if (SOCKET_ERRNO != EWOULDBLOCK &&
                    SOCKET_ERRNO != WSAEWOULDBLOCK)
                {

#  else
                if (SOCKET_ERRNO != EWOULDBLOCK)
                {
#  endif
                    closeConn(cp, PS_PLATFORM_FAIL);
                    continue;   /* Next connection */
                }
            }
            else
            {
                /* Indicate that we've written > 0 bytes of data */
                if ((rc = matrixSslSentData(cp->ssl, transferred)) < 0)
                {
                    closeConn(cp, PS_ARG_FAIL);
                    continue;   /* Next connection */
                }
                if (rc == MATRIXSSL_REQUEST_CLOSE)
                {
                    closeConn(cp, MATRIXSSL_REQUEST_CLOSE);
                    continue;   /* Next connection */
                }
                else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
                {
                    Printf("Got HANDSHAKE_COMPLETE from SentData\n");
                    /* If the protocol is server initiated, send data here */
                    cp->handshakeComplete = 1;
                    g_handshakes++;
# ifdef USE_REHANDSHAKING
                    if (g_doSelfInitiatedRehandshakeTest &&
                            g_numRehandshakes < g_maxRehandshakes)
                    {
                        /* Full rehandshake */
                        Printf("Server initiating re-handshake\n");
                        if (matrixSslEncodeRehandshake(cp->ssl, NULL,
# ifdef USE_CLIENT_AUTH
                                        g_require_client_auth ? certCb : NULL,
# else
                                        NULL,
# endif /* USE_CLIENT_AUTH */
                                        SSL_OPTION_FULL_HANDSHAKE, NULL, 0) < 0)
                        {
                            Printf("matrixSslEncodeRehandshake failed\n");
                            exit(1);
                        }
                        g_numRehandshakes++;
                    }
#endif /* USE_REHANDSHAKING */
#  ifdef ENABLE_FALSE_START
                    /* OR this could be a Chrome browser using
                        FALSE_START and the application data is already
                        waiting in our inbuf for processing */
                    if ((rc = matrixSslReceivedData(cp->ssl, 0,
                             &buf, (uint32 *) &len)) < 0)
                    {
                        closeConn(cp, 0);
                        continue; /* Next connection */
                    }
                    if (rc > 0)   /* There was leftover data */
                    {
                        goto PROCESS_MORE;
                    }
#  endif            /* ENABLE_FALSE_START  */

                }
                /* Update activity time */
                psGetTime(&cp->time, NULL);
                /* Try to send again if more data to send */
                if (rc == MATRIXSSL_REQUEST_SEND || transferred < len)
                {
                    if (wSanity++ < GOTO_SANITY)
                    {
                        goto WRITE_MORE;
                    }
                }
            }
        }
        else if (len < 0)
        {
            closeConn(cp, PS_ARG_FAIL);
            continue;   /* Next connection */
        }

        /* If we are sending response data and it's all encoded and sent, close conn.
           Do not close connection if handshake is not finished which is the case with
           TLS1.3 early data */
        if (cp->handshakeComplete == 1 && cp->bytes_requested > 0 &&
            cp->bytes_requested == cp->bytes_sent &&
            matrixSslGetOutdata(cp->ssl, &buf) <= 0)
        {
            closeConn(cp, PS_SUCCESS);
            continue;   /* Next connection */
        }

/*
        Check the file descriptor returned from select to see if the connection
        has data to be read
 */
        if (FD_ISSET(cp->fd, &readfd))
        {
READ_MORE:
            /* Get the ssl buffer and how much data it can accept */
            /* Note 0 is a return failure, unlike with matrixSslGetOutdata */
            if ((len = matrixSslGetReadbuf(cp->ssl, &buf)) <= 0)
            {
                closeConn(cp, PS_ARG_FAIL);
                continue;   /* Next connection */
            }
            if ((transferred = (int32) recv(cp->fd, buf, len, MSG_DONTWAIT)) < 0)
            {
                /* We could get EWOULDBLOCK despite the FD_ISSET on goto  */
#  ifdef WIN32
                if (SOCKET_ERRNO != EWOULDBLOCK &&
                    SOCKET_ERRNO != WSAEWOULDBLOCK)
                {

#  else
                if (SOCKET_ERRNO != EWOULDBLOCK)
                {
#  endif
                    closeConn(cp, PS_PLATFORM_FAIL);
                }
                continue;   /* Next connection */
            }
                psTraceBytes("+++ Got", buf, transferred);
            /* If EOF, remote socket closed. This is semi-normal closure.
               Officially, we should close on closure alert. */
            if (transferred == 0)
            {
/*                              psTraceIntInfo("Closing connection %d on EOF\n", cp->fd); */
                closeConn(cp, 0);
                continue; /* Next connection */
            }
/*
            Notify SSL state machine that we've received more data into the
            ssl buffer retreived with matrixSslGetReadbuf.
 */
            if ((rc = matrixSslReceivedData(cp->ssl, (int32) transferred, &buf,
                     (uint32 *) &len)) < 0)
            {
                closeConn(cp, 0);
                continue;   /* Next connection */
            }
            /* Update activity time */
            psGetTime(&cp->time, NULL);

PROCESS_MORE:
            /* Process any incoming plaintext application data */
            switch (rc)
            {
            case MATRIXSSL_HANDSHAKE_COMPLETE:
                Printf("Got HANDSHAKE_COMPLETE from RecvData\n");
                cp->handshakeComplete = 1;
                g_handshakes++;
                /* If the protocol is server initiated, send data here */
                goto READ_MORE;
            case MATRIXSSL_APP_DATA:
            case MATRIXSSL_APP_DATA_COMPRESSED:
                psTraceBytes("App data from client", buf, len);

                /* First test to see if this is one of the special data
                    requests used for testing.

                     First is a "GET /bytes?<byteCount>" format
                 */
                specialAppData = 0;
                if (len > 11 &&
                    Strncmp((char *) buf, "GET /bytes?", 11) == 0)
                {
                    cp->bytes_requested = atoi((char *) buf + 11);
                    if (cp->bytes_requested <
                        Strlen((char *) g_httpResponseHdr) ||
                        cp->bytes_requested > 1073741824)
                    {
                        cp->bytes_requested =
                            (uint32) Strlen((char *) g_httpResponseHdr);
                    }
                    cp->bytes_sent = 0;
                    specialAppData = 1;
                }
                /* A special test for TLS 1.0 where BEAST workaround used */
                if (len > 10 &&
                    Strncmp((char *) buf, "ET /bytes?", 10) == 0)
                {
                    cp->bytes_requested = atoi((char *) buf + 10);
                    if (cp->bytes_requested <
                        Strlen((char *) g_httpResponseHdr) ||
                        cp->bytes_requested > 1073741824)
                    {
                        cp->bytes_requested =
                            (uint32) Strlen((char *) g_httpResponseHdr);
                    }
                    cp->bytes_sent = 0;
                    specialAppData = 1;
                }
                /* Shutdown the server */
                if (len >= 15 &&
                    Strncmp((char *) buf, "MATRIX_SHUTDOWN", 15) == 0)
                {
                    g_exitFlag = 1;
                    rc = matrixSslEncodeClosureAlert(cp->ssl);
                    psAssert(rc >= 0);
                    psTrace("Got MATRIX_SHUTDOWN.  Exiting\n");
                    goto WRITE_MORE;
                }

                if (specialAppData == 0)
                {
                    if ((rc = httpBasicParse(cp, buf, len, 0)) < 0)
                    {
                        psTrace("Couldn't parse HTTP data.  Closing...\n");
                        closeConn(cp, PS_PROTOCOL_FAIL);
                        continue;     /* Next connection */
                    }
                }

                if (rc == HTTPS_COMPLETE || specialAppData == 1)
                {
                    if (httpWriteResponse(cp) < 0)
                    {
                        closeConn(cp, PS_PROTOCOL_FAIL);
                        continue;     /* Next connection */
                    }
                    /* For HTTP, we assume no pipelined requests, so we
                       close after parsing a single HTTP request */
                    /* Ignore return of closure alert, it's optional */
#  ifdef SEND_CLOSURE_ALERT
/*                                              rc = matrixSslEncodeClosureAlert(cp->ssl); */
/*                                              psAssert(rc >= 0); */
#  endif
                    rc = matrixSslProcessedData(cp->ssl, &buf, (uint32 *) &len);
                    if (!cp->handshakeComplete)
                    {
                        /* If handshake is not yet completed we received
                           TLS1.3 early data. Continue the handshake based
                           on the result */
                        if (rc == MATRIXSSL_REQUEST_SEND)
                        {
                            goto WRITE_MORE;
                        }
                        if (rc == MATRIXSSL_REQUEST_RECV)
                        {
                            goto READ_MORE;
                        }
                    }
                    if (rc > 0)
                    {
                        /* Additional data is available, but we ignore it */
                        psTrace("HTTP data parsing not supported, ignoring.\n");
                        closeConn(cp, PS_SUCCESS);
                        continue;     /* Next connection */
                    }
                    else if (rc < 0)
                    {
                        closeConn(cp, PS_PROTOCOL_FAIL);
                        continue;     /* Next connection */
                    }
                    /* rc == 0, write out our response and closure alert */
                    goto WRITE_MORE;
                }
                /* We processed a partial HTTP message */
                if ((rc = matrixSslProcessedData(cp->ssl, &buf, (uint32 *) &len)) == 0)
                {
                    goto READ_MORE;
                }
                goto PROCESS_MORE;
            case MATRIXSSL_REQUEST_SEND:
                /* Prevent us from reading again after the write,
                   although that wouldn't be the end of the world */
                FD_CLR(cp->fd, &readfd);
                if (wSanity++ < GOTO_SANITY)
                {
                    goto WRITE_MORE;
                }
                break;
            case MATRIXSSL_REQUEST_RECV:
                if (rSanity++ < GOTO_SANITY)
                {
                    goto READ_MORE;
                }
                break;
            case MATRIXSSL_RECEIVED_ALERT:
                /* The first byte of the buffer is the level */
                /* The second byte is the description */
                if (*buf == SSL_ALERT_LEVEL_FATAL)
                {
                    psTraceInt("Fatal alert: %d, closing connection.\n",
                        *(buf + 1));
                    closeConn(cp, PS_PROTOCOL_FAIL);
                    continue;     /* Next connection */
                }
                /* Closure alert is normal (and best) way to close */
                if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY)
                {
                    closeConn(cp, PS_SUCCESS);
                    continue;     /* Next connection */
                }
                psTraceInt("Warning alert: %d\n", *(buf + 1));
                if ((rc = matrixSslProcessedData(cp->ssl, &buf, (uint32 *) &len)) == 0)
                {
                    /* No more data in buffer. Might as well read for more. */
                    goto READ_MORE;
                }
                goto PROCESS_MORE;

            default:
                /* If rc <= 0 we fall here */
                closeConn(cp, PS_PROTOCOL_FAIL);
                continue;     /* Next connection */
            }
            /* Always try to read more if we processed some data */
            if (rSanity++ < GOTO_SANITY)
            {
                goto READ_MORE;
            }
        } /*  readfd handling */
    }   /* connection loop */
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Create an HTTP response and encode it to the SSL buffer
 */
#  define TEST_SIZE   16000
static int32 httpWriteResponse(httpConn_t *cp)
{
    unsigned char *buf;
    ssl_t *ssl;
    int32 len, rc;

    ssl = cp->ssl;
    /* The /bytes? HTTP request assigns bytes_requested */
    if (cp->bytes_requested)
    {
        /*
            Generate TLS records for all the requested bytes.
            This can put a lot of data in ssl outbuf, so we attempt
            to flush it out at the bottom of the loop.
            Anything left over will be sent out in the main server loop.
         */
        while (cp->bytes_sent < cp->bytes_requested)
        {
            len = cp->bytes_requested - cp->bytes_sent;
            if (len < 0)
            {
                return PS_MEM_FAIL;
            }
            if (len > RESPONSE_REC_LEN)
            {
                len = RESPONSE_REC_LEN;
            }
            if ((rc = matrixSslGetWritebuf(ssl, &buf, len)) < 1)
            {
                return PS_MEM_FAIL;
            }
            if (rc < len)
            {
                len = rc; /* could have been shortened due to max_frag */
            }
            Memset(buf, 'A', len);
            if (cp->bytes_sent == 0)
            {
                /* Overwrite first N bytes with HTTP header the first time */
                Strncpy((char *) buf, (char *) g_httpResponseHdr,
                    Strlen((char *) g_httpResponseHdr));
            }
            if ((rc = matrixSslEncodeWritebuf(ssl, len)) < 0)
            {
                Printf("couldn't encode data %d\n", rc);
            }
            cp->bytes_sent += len;
            /*
                Do a quick, non-blocking send here to start flushing the
                generated records. We could flush after each record encode,
                or only on a multiple of record encodes.
             */
            if (matrixSslGetOutdata(ssl, &buf) > (RESPONSE_REC_LEN * 4))
            {
                if ((len = (int32) send(cp->fd, buf, len, MSG_DONTWAIT)) > 0)
                {
                    psTraceBytes("++ sent:", buf, len);
                    rc = matrixSslSentData(ssl, len);
/*                                      psAssert(rc != MATRIXSSL_REQUEST_SEND); / * Some data remains * / */
                }
            }
        }
        return MATRIXSSL_REQUEST_SEND;
    }

# ifdef USE_TLS_1_3
    if (matrixSslGetNegotiatedVersion(ssl) & v_tls_1_3_any)
    {
        rc = sendHtmlResponseTls13(ssl);
    }
    else
    {
        rc = sendHtmlResponse(ssl);
    }
# else
    rc = sendHtmlResponse(ssl);
# endif /* USE_TLS_1_3 */

    if (rc != PS_SUCCESS)
    {
        return rc;
    }

    return MATRIXSSL_REQUEST_SEND;
}

# ifdef USE_TLS_1_3
static int32_t sendHtmlResponseTls13(ssl_t *ssl)
{
    uint32_t len;
    int32_t available;
    int32_t rc;
    unsigned char *buf;

    len = (uint32) Strlen(g_httpResponseHeaderTls13) + 1;
    printf("length: %zu\n", Strlen(g_httpResponseHeaderTls13));
    available = matrixSslGetWritebuf(ssl, &buf, len);
    if (available < 0)
    {
        return PS_MEM_FAIL;
    }
    Strncpy((char*)buf, g_httpResponseHeaderTls13, len);
    rc = matrixSslEncodeWritebuf(ssl, len);
    if (rc < 0)
    {
        return PS_MEM_FAIL;
    }
    rc = matrixSslEncodeClosureAlert(ssl);

    return rc;
}
# endif

static int32_t sendHtmlResponse(ssl_t *ssl)
{
    int32_t available;
    int32_t rc;
    unsigned char *buf;

    available = matrixSslGetWritebuf(ssl, &buf,
            (uint32) Strlen((char *) g_httpResponseHdr) + 1);
    if (available < 0)
    {
        return PS_MEM_FAIL;
    }
    Strncpy((char *) buf, (char *) g_httpResponseHdr, available);

    rc = matrixSslEncodeWritebuf(ssl, (uint32) Strlen((char *) buf));
    if (rc < 0)
    {
        return PS_MEM_FAIL;
    }

    return PS_SUCCESS;
}

static void usage(void)
{
    Printf(
        "\nusage: server { options }\n"
        "\n"
        "Options can be one or more of the following:\n"
        "\n"
        "-c <file>           - Server certificate file\n"
        "-k <file>           - Server private key file of certificate\n"
        "-a <file>           - CA certificate file\n"
        "-A                  - Require client authentication\n"
        "-K                  - Use a test PSK in TLS 1.3 handshakes\n"
        "-p <pass>           - Private key password\n"
        "-d <file>           - Diffie-Hellman parameters file\n"
        "-g <groups>         - (TLS 1.3 only): Colon-separated list of\n"
        "                      TLS 1.3 NamedGroups to support for key exchange.\n"
        "-D <dir>            - Directory path to certificate, private key, \n"
        "                       and Diffie-Hellman parameter files\n"
        "-P <port>           - Port number\n"
        "-h                  - Help, print usage and exit\n"
        "-x <ciphers>        - Cipher suites to disable\n"
        "                      Example cipher numbers:\n"
        "                        - '53' TLS_RSA_WITH_AES_256_CBC_SHA\n"
        "                        - '47' TLS_RSA_WITH_AES_128_CBC_SHA\n"
        "                        - '10' SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
        "                        - '5'  SSL_RSA_WITH_RC4_128_SHA\n"
        "                        - '4'  SSL_RSA_WITH_RC4_128_MD5\n"
        "-v <tlsVersion>     - Select single SSL/TLS version to use\n"
        "                        - '0' SSL 3.0\n"
        "                        - '1' TLS 1.0\n"
        "                        - '2' TLS 1.1\n"
        "                        - '3' TLS 1.2 (default)\n"
        "                        - '4' TLS 1.3\n"
        "-V <min>,<max>      - SSL/TLS version range to use, e.g. '-V 2,3'\n"
        "                    - Note: Only one of -v, -V or -W should be supplied\n"
        "-W <min>,<max>      - SSL/TLS enabled versions in priority order, e.g. '-W 4,2\n"
        "                    - Note: Only one of -v, -V or -W should be supplied\n"
        "-S <sigAlgs>        - Supported signature algorithms.\n"
        "                      For example: ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256\n"
        "-C <sigAlgsCert>    - Supported signature algorithms in TLS1.3 certs.\n"
        "                      For example: ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256\n"
        "-E <maxEarlyData>   - Enable early data support for TLS1.3 with maximum accepted amount.\n"
        "                    - Maximum early data is 16384 bytes\n"
        "-b <block size>     - Block size to pad TLS 1.3 records to.\n"
        "-o/-O               - Load a test OCSP response (-o: good, -O: revoked)\n"
        "                      Requires -c testkeys/EC/256_EC.pem to work.\n"
        "\n");

}

/* Returns number of cipher numbers found, or -1 if an error. */
#  include "osdep_ctype.h"
static int32_t parse_cipher_list(char *cipherListString,
    psCipher16_t cipher_array[], uint8_t size_of_cipher_array)
{
    uint32 numCiphers, cipher;
    char *endPtr;

    /* Convert the cipherListString into an array of cipher numbers. */
    numCiphers = 0;
    while (cipherListString != NULL)
    {
        cipher = Strtol(cipherListString, &endPtr, 10);
        if (endPtr == cipherListString)
        {
            Printf("The remaining cipherList has no cipher numbers - '%s'\n",
                cipherListString);
            return -1;
        }
        else if (size_of_cipher_array <= numCiphers)
        {
            Printf("Too many cipher numbers supplied.  limit is %d\n",
                size_of_cipher_array);
            return -1;
        }
        cipher_array[numCiphers++] = cipher;
        while (*endPtr != '\0' && !Isdigit(*endPtr))
        {
            endPtr++;
        }
        cipherListString = endPtr;
        if (*endPtr == '\0')
        {
            break;
        }
    }

    return numCiphers;
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
    int optionChar, str_len, numCiphers;
    char *cipherListString;
    psList_t *versionRangeList;
    psProtocolVersion_t version;

    /* Start with all options zeroized. */
    Memset(g_keyfilePath, 0, MAX_KEYFILE_PATH);
    Memset(g_privkeyFile, 0, MAX_KEYFILE_PATH);
    Memset(g_serverName, 0, MAX_SERVER_NAME);
    Memset(g_identityCert, 0, MAX_KEYFILE_PATH);
    Memset(g_dhParamFile, 0, MAX_KEYFILE_PATH);
    Memset(g_caFile, 0, MAX_KEYFILE_PATH);
    Memset(g_password, 0, MAX_PASSWORD_LEN);

    g_port = HTTPS_PORT;
    g_min_version = g_max_version = v_tls_1_2;
    g_disabledCiphers = 0;

    opterr = 0;
    while ((optionChar = getopt(argc,
                            argv,
                            "c:d:g:a:Bb:AD:hKk:n:oOp:P:v:V:x:r:S:C:W:E:")) != -1)
    {
        switch (optionChar)
        {
        case 'h':
            return -1;

        case 'x':
            /* Ciphers to DISABLE! */
            /* Convert the cipherListString into an array of cipher numbers. */
            cipherListString = optarg;
            numCiphers = parse_cipher_list(cipherListString, g_disabledCipher,
                SSL_MAX_DISABLED_CIPHERS);
            if (numCiphers <= 0)
            {
                return -1;
            }
            g_disabledCiphers = numCiphers;
            break;

        case 'D':
            /* Directory for key and cert location */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_keyfilePath, optarg, str_len);
            break;

        case 'c':
            /* Certfile */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_identityCert, optarg, str_len);
            break;

        case 'a':
            /* Cert authority file */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_caFile, optarg, str_len);
            break;

        case 'A':
            /* Require client authentication. */
            g_require_client_auth = 1;
            break;

        case 'b':
            /* TLS 1.3 block size. */
            {
                char *end;

                g_tls13_block_size = Strtol(optarg, &end, 10);
                if (end == optarg
                        || g_tls13_block_size < 0
                        || g_tls13_block_size > TLS_1_3_MAX_INNER_PLAINTEXT_LEN)
                {
                    Printf("Invalid tls13-block-size argument\n");
                    exit(EXIT_FAILURE);
                }
                Printf("Using TLS 1.3 block side %ld\n", g_tls13_block_size);
                break;
            }

        case 'B':
            /* Allow the server to load an out-of-date certificate chain. */
            g_allow_out_of_date_cert_chain = 1;
            break;

        case 'd':
            /* Diffie-Hellman parameters */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_dhParamFile, optarg, str_len);
            break;

        case 'g':
            /* Key exchange groups to support. */
            if (psParseList(NULL, optarg, ':', &g_groupList) < 0)
            {
                Printf("Invalid group list: %s\n", optarg);
            }
            break;

        case 'k':
            /* Keyfile */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_privkeyFile, optarg, str_len);
            break;

        case 'K':
            /* PSK. TODO: use the PSK provided in optarg. Now this arg
               causes us to perform a PSK handshake using the use the
               TLS 1.3 PSK (testkeys/PSK/tls13_psk.h). */
            g_use_psk = 1;
            break;

        case 'n':
            /* Server name. */
            str_len = Strlen(optarg);
            if (str_len > MAX_SERVER_NAME - 1)
            {
                return -1;
            }
            Strncpy(g_serverName, optarg, str_len);
            break;
# ifdef USE_OCSP_RESPONSE
        case 'o':
            /* Test OCSP stapling with a "good" response. */
            g_test_ocsp_stapling_good = 1;
            break;
        case 'O':
            /* Test OCSP stapling with a "revoked" response.
               Note that for this test to work, the 256_EC.pem
               server cert should be used. */
            g_test_ocsp_stapling_revoked = 1;
            break;
# endif

        case 'p':
            /* password */
            str_len = Strlen(optarg);
            if (str_len > MAX_KEYFILE_PATH - 1)
            {
                return -1;
            }
            Strncpy(g_password, optarg, str_len);
            break;

        case 'P':
            g_port = atoi(optarg);
            break;

        case 'r':
#ifdef USE_REHANDSHAKING
            g_doSelfInitiatedRehandshakeTest = 1;
            g_maxRehandshakes = atoi(optarg);
#else
            Printf("Need USE_REHANDSHAKING for re-handshake test\n");
            exit(EXIT_FAILURE);
#endif
            break;

        case 'v':
            /* Single version. */
            version = matrixSslVersionFromMinorDigit(atoi(optarg));
            if (!matrixSslTlsVersionRangeSupported(version,
                            version))
            {
                Printf("Invalid version: %d\n", version);
                return -1;
            }
            g_min_version = g_max_version = version;
            break;

        case 'V':
            if (psParseList(NULL, optarg, ',', &versionRangeList) < 0 ||
                versionRangeList->next == NULL)
            {
                Printf("Invalid version range string: %s\n",
                        optarg);
                psFreeList(versionRangeList, NULL);
                return -1;
            }
            g_min_version = matrixSslVersionFromMinorDigit(
                    atoi((char *)versionRangeList->item));
            g_max_version = matrixSslVersionFromMinorDigit(
                    atoi((char *)versionRangeList->next->item));
            psFreeList(versionRangeList, NULL);
            if (!matrixSslTlsVersionRangeSupported(g_min_version,
                            g_max_version))
            {
                Printf("Unsupported version range: %s\n",
                        optarg);
                return -1;
            }
            break;
        case 'W':
            if (psParseList(NULL, optarg, ',', &g_supportedVersionsList) < 0)
            {
                Printf("Invalid tls-supported-versions list: %s\n", optarg);
            }
            if (Strcmp((char*)g_supportedVersionsList[0].item, "default") == 0)
            {
                g_use_default_versions = 1;
            }
            break;
        case 'S':
            if (psParseList(NULL, optarg, ':', &g_sigAlgsList) < 0)
            {
                Printf("Invalid sig_alg list: %s\n", optarg);
            }
            break;
        case 'C':
            if (psParseList(NULL, optarg, ':', &g_sigAlgsCertList) < 0)
            {
                Printf("Invalid sig_alg_cert list: %s\n", optarg);
            }
            break;
        case 'E':
            if (optarg != NULL)
            {
                g_max_early_data = atoi(optarg);
            }
            else
            {
                g_max_early_data = 16384;
            }
            break;
        }
    }

    return 0;
}


/******************************************************************************/
/*
    Main non-blocking SSL server
    Initialize MatrixSSL and sockets layer, and loop on select
 */
int32 main(int32 argc, char **argv)
{
    SOCKET lfd;
    int32 err, rc;

#  ifdef WIN32
    WSADATA wsaData;
#  endif
#  ifdef USE_STATELESS_SESSION_TICKETS
    unsigned char sessTicketName[16];
#  endif
    char certpath[FILENAME_MAX];
    char keypath[FILENAME_MAX];
    char capath[FILENAME_MAX];
    sslKeys_t *keys = NULL;

#  ifdef WIN32
    WSAStartup(MAKEWORD(1, 1), &wsaData);
#  endif

    DLListInit(&g_conns);
    g_exitFlag = 0;
    lfd = INVALID_SOCKET;

#  ifdef POSIX
    if (sighandlers() < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  endif /* POSIX */

    if ((rc = matrixSslOpen()) < 0)
    {
        psTrace("MatrixSSL library init failure.  Exiting\n");
        return rc;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        return -1;
    }

    if (0 != process_cmd_options(argc, argv))
    {
        matrixSslDeleteKeys(keys);
        usage();
        return 0;
    }

#  ifdef MATRIX_USE_FILE_SYSTEM
    if (cwdIsMatrixRoot())
    {
        key_dir = testkeys_root;
    }
    else
    {
        key_dir = testkeys_apps_ssl;
    }
#  endif
#  ifdef USE_STATELESS_SESSION_TICKETS
    if (psGetPrngLocked(sessTicketSymKey, sizeof(sessTicketSymKey), NULL) < 0
        || psGetPrngLocked(sessTicketMacKey, sizeof(sessTicketMacKey), NULL) < 0
        || psGetPrngLocked(sessTicketName, sizeof(sessTicketName), NULL) < 0)
    {
        psTrace("Error generating session ticket encryption key\n");
        matrixSslDeleteKeys(keys);
        return EXIT_FAILURE;
    }
    if (matrixSslLoadSessionTicketKeys(keys, sessTicketName,
            sessTicketSymKey, sizeof(sessTicketSymKey),
            sessTicketMacKey, sizeof(sessTicketMacKey)) < 0)
    {
        psTrace("Error loading session ticket encryption key\n");
        return EXIT_FAILURE;
    }
    matrixSslSetSessionTicketCallback(keys, sessTicketCb);
    psTrace("Session Ticket resumption enabled\n");
#  endif


    /* Set the certpath and keypath as the defaults or the user provided */
    if (g_identityCert[0] != 0)
    {
        /* User provided a cert */
        if (g_keyfilePath[0] != 0)
        {
            Snprintf(certpath, FILENAME_MAX - 1, "%s/%s",
                g_keyfilePath, g_identityCert);
        }
        else
        {
            Snprintf(certpath, FILENAME_MAX - 1, "%s", g_identityCert);
        }
    }
    else
    {
        /* Default cert */
        psTrace("WARNING: Do not use sample certificate file in production\n");
        Snprintf(certpath, FILENAME_MAX - 1, "%s/%s",
            key_dir, g_defaultCertFile);
    }

    if (g_privkeyFile[0] != 0)
    {
        /* User provided a key */
        if (g_keyfilePath[0] != 0)
        {
            Snprintf(keypath, FILENAME_MAX - 1, "%s/%s",
                g_keyfilePath, g_privkeyFile);
        }
        else
        {
            Snprintf(keypath, FILENAME_MAX - 1, "%s", g_privkeyFile);
        }
    }
    else
    {
        /* Default key */
        psTrace("WARNING: Do not use sample private key file in production\n");
        Snprintf(keypath, FILENAME_MAX - 1, "%s/%s",
            key_dir, g_defaultPrivkeyFile);
    }

    if (g_caFile[0] != 0)
    {
        /* User provided a CA file */
        if (g_keyfilePath[0] != 0)
        {
            Snprintf(capath, FILENAME_MAX - 1, "%s/%s",
                g_keyfilePath, g_caFile);
        }
        else
        {
            Snprintf(capath, FILENAME_MAX - 1, "%s", g_caFile);
        }
    }
    else
    {
        /* Default key */
        Snprintf(capath, FILENAME_MAX - 1, "%s/%s",
            key_dir, g_defaultCAFile);
    }

# ifdef USE_TLS_1_3
    if (g_use_psk)
    {
        /* Load the TLS 1.3 test SHA-256 based PSK. */
        rc = matrixSslLoadTls13Psk(keys,
                g_tls13_test_psk_256,
                sizeof(g_tls13_test_psk_256),
                g_tls13_test_psk_id_sha256,
                sizeof(g_tls13_test_psk_id_sha256),
                NULL);
        if (rc < 0)
        {
            psTrace("Unable to load PSK keys.\n");
            return rc;
        }
#  ifdef USE_TLS_AES_256_GCM_SHA384
        /* Add the SHA-384 PSK. */
        rc = matrixSslLoadTls13Psk(keys,
                g_tls13_test_psk_384,
                sizeof(g_tls13_test_psk_384),
                g_tls13_test_psk_id_sha384,
                sizeof(g_tls13_test_psk_id_sha384),
                NULL);
        if (rc < 0)
        {
            psTrace("Unable to load PSK keys.\n");
            return rc;
        }
#  endif
    }
# endif

# if !defined(USE_ONLY_PSK_CIPHER_SUITE)
    {
        matrixSslLoadKeysOpts_t loadKeysOpts;

        Memset(&loadKeysOpts, 0, sizeof(loadKeysOpts));

        if (g_allow_out_of_date_cert_chain)
        {
            loadKeysOpts.flags = LOAD_KEYS_OPT_ALLOW_OUT_OF_DATE_CERT_PARSE;
        }
        rc = matrixSslLoadKeys(keys,
                certpath,
                keypath,
                g_password,
                capath,
                &loadKeysOpts);
        if (rc < 0)
        {
            psTrace("Unable to load key material.  Exiting\n");
            return rc;
        }
    }
# endif

#  ifdef USE_OCSP_RESPONSE
    {
        if (g_test_ocsp_stapling_good)
        {
#       include "testkeys/OCSP/responses/OCSP_256_EC_GOOD.h"

            rc = matrixSslLoadOCSPResponse(keys,
                    ocsp_256_ec_good,
                    sizeof(ocsp_256_ec_good));
            if (rc < 0)
            {
                psTraceInt("matrixSslLoadOCSPResponse failed: %d\n", rc);
            }
            psTrace("Good OCSP response loaded for 256_EC.pem\n");
        }
        else if (g_test_ocsp_stapling_revoked)
        {
#       include "testkeys/OCSP/responses/OCSP_256_EC_REVOKED.h"

            rc = matrixSslLoadOCSPResponse(keys,
                    ocsp_256_ec_revoked,
                    sizeof(ocsp_256_ec_revoked));
            if (rc < 0)
            {
                psTraceInt("matrixSslLoadOCSPResponse failed: %d\n", rc);
            }
            psTrace("Revoked OCSP response loaded for 256_EC.pem\n");
        }
    }
#  endif

#  ifdef REQUIRE_DH_PARAMS
    if (g_dhParamFile[0] != 0)
    {
        /* User provided DH params */
        if (g_keyfilePath[0] != 0)
        {
            Snprintf(certpath, FILENAME_MAX - 1, "%s/%s",
                g_keyfilePath, g_dhParamFile);
        }
        else
        {
            Snprintf(certpath, FILENAME_MAX - 1, "%s", g_dhParamFile);
        }
    }
    else
    {
        /* Default DH params */
        Snprintf(certpath, FILENAME_MAX - 1, "%s/%s",
            key_dir, g_defaultDHParamFile);
    }
    if ((rc = matrixSslLoadDhParams(keys, certpath)) < 0)
    {
        psTrace("Unable to load static key material.  Exiting\n");
        return rc;
    }
#  endif

    /* Were any cipher suites disabled? */
    if (g_disabledCiphers > 0)
    {
        for (rc = 0; rc < g_disabledCiphers; rc++)
        {
            /* Global disable.  Per-session disables would be done immediately
                following matrixSslNewServerSession if desired */
            matrixSslSetCipherSuiteEnabledStatus(NULL, g_disabledCipher[rc],
                PS_FALSE);
        }
    }

    /* Create the listening socket that will accept incoming connections */
    if ((lfd = lsocketListen(g_port, &err)) == INVALID_SOCKET)
    {
        psTraceInt("Can't listen on port %d\n", g_port);
        goto L_EXIT;
    }

    /* Main select loop to handle sockets events */
    while (!g_exitFlag)
    {
        selectLoop(keys, lfd);
        displayStats();
    }

    /* Close any active connections */
    while (!DLListIsEmpty(&g_conns))
    {
        httpConn_t *cp;
        DLListEntry *pList;
        pList = DLListGetHead(&g_conns);
        cp = DLListGetContainer(pList, httpConn_t, List);
        closeConn(cp, PS_SUCCESS);
    }

L_EXIT:
    if (lfd != INVALID_SOCKET)
    {
        close(lfd);
    }
    matrixSslDeleteKeys(keys);
    matrixSslClose();
    psFreeList(g_groupList, NULL);
    psFreeList(g_sigAlgsCertList, NULL);
    psFreeList(g_sigAlgsList, NULL);
    psFreeList(g_supportedVersionsList, NULL);
    return 0;
}

/******************************************************************************/
/*
    Close a socket and free associated SSL context and buffers
 */
static void closeConn(httpConn_t *cp, int32 reason)
{
#  ifdef SEND_CLOSURE_ALERT
    unsigned char *buf;
#  endif
    int32 len;

    DLListRemove(&cp->List);
#  ifdef SEND_CLOSURE_ALERT
    /* Quick attempt to send a closure alert, don't worry about failure */
    if (matrixSslEncodeClosureAlert(cp->ssl) >= 0)
    {
        if ((len = matrixSslGetOutdata(cp->ssl, &buf)) > 0)
        {
            /* psTraceBytes("closure alert", buf, len); */
            if ((len = (int32) send(cp->fd, buf, len, MSG_DONTWAIT)) > 0)
            {
                psTraceBytes("++ sent:", buf, len);
                matrixSslSentData(cp->ssl, len);
            }
        }
    }
#  endif
    if (cp->parsebuf != NULL)
    {
        psAssert(cp->parsebuflen > 0);
        Free(cp->parsebuf);
        cp->parsebuflen = 0;
    }

    matrixSslDeleteSession(cp->ssl);

    if (cp->fd != INVALID_SOCKET)
    {
        close(cp->fd);
    }
    if (reason >= 0)
    {
/*              psTraceInt("=== Closing Client %d ===\n", cp->fd); */
    }
    else
    {
        psTraceInt("=== Closing Client %d on Error ===\n", cp->fd);
    }
    Free(cp);
}

/******************************************************************************/
/*
    Establish a listening socket for incomming connections
 */
static SOCKET lsocketListen(short port, int32 *err)
{
    struct sockaddr_in addr = { 0 };
    SOCKET fd;

    if ((fd = Socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        psTrace("Error creating listen socket\n");
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }

    if (setSocketOptions(fd) < 0)
    {
        close(fd);
        return INVALID_SOCKET;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        close(fd);
        psTrace("Can't bind socket. Port in use or insufficient privilege\n");
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }
    if (listen(fd, SOMAXCONN) < 0)
    {
        close(fd);
        psTrace("Error listening on socket\n");
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }
    psTraceInt("Listening on port %d\n", port);
    return fd;
}

/******************************************************************************/
/*
    Make sure the socket is not inherited by exec'd processes
    Set the REUSE flag to minimize the number of sockets in TIME_WAIT
    Then we set REUSEADDR, NODELAY and NONBLOCK on the socket
 */
static int setSocketOptions(SOCKET fd)
{
    int rc;

#  ifdef POSIX
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  endif
    rc = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &rc, sizeof(rc)) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  ifdef POSIX
    rc = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &rc, sizeof(rc)) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  elif defined(WIN32)
    rc = 1;     /* 1 for non-block, 0 for block */
    if (ioctlsocket(fd, FIONBIO, &rc) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  endif
#  ifdef __APPLE__ /* MAC OS X */
    rc = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *) &rc, sizeof(rc)) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
#  endif
    return PS_SUCCESS;
}

#  ifdef POSIX
/******************************************************************************/
/*
    Handle some signals on POSIX platforms
    Lets ctrl-c do a clean exit of the server.
 */
static int32 sighandlers(void)
{
    if (Signal(SIGINT, sigintterm_handler) == SIG_ERR ||
        Signal(SIGTERM, sigintterm_handler) == SIG_ERR ||
        Signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
        Signal(SIGSEGV, sigsegv_handler) == SIG_ERR)
    {
        return PS_PLATFORM_FAIL;
    }
    return 0;
}

/* Warn on segmentation violation */
static void sigsegv_handler(int unused)
{
    Printf("Segfault! Please report this as a bug to support@peersec.com\n");
    exit(EXIT_FAILURE);
}

/* catch ctrl-c or sigterm */
static void sigintterm_handler(int unused)
{
    g_exitFlag = 1; /* Rudimentary exit flagging */
    Printf("Exiting due to interrupt.\n");
}
#  endif /* POSIX */


# else

/******************************************************************************/
/*
    Stub main for compiling without server enabled
 */
int32 main(int32 argc, char **argv)
{
    Printf("USE_SERVER_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
        " time to run this application\n");
    return -1;
}
# endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/

#else
# include "osdep_stdio.h"

int main(int argc, char **argv)
{
    Printf("You need to #define MATRIX_USE_FILE_SYSTEM for this test\n");
    return 1;
}

#endif /* MATRIX_USE_FILE_SYSTEM */
