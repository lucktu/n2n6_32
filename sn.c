/* Supernode for n2n-2.x */

/* (c) 2009 Richard Andrews <andrews@ntop.org>
 *
 * Contributions by:
 *    Lukasz Taczuk
 *    Struan Bartlett
 */


#include "n2n.h"


#define N2N_SN_LPORT_DEFAULT SUPERNODE_PORT
#define N2N_SN_PKTBUF_SIZE   2048

#define N2N_SN_MGMT_PORT                5645

#ifndef _WIN32
#include <poll.h>
#endif

struct sn_stats
{
    size_t errors;              /* Number of errors encountered. */
    size_t reg_super;           /* Number of REGISTER_SUPER requests received. */
    size_t reg_super_nak;       /* Number of REGISTER_SUPER requests declined. */
    size_t fwd;                 /* Number of messages forwarded. */
    size_t broadcast;           /* Number of messages broadcast to a community. */
    time_t last_fwd;            /* Time when last message was forwarded. */
    time_t last_reg_super;      /* Time when last REGISTER_SUPER was received. */
};

typedef struct sn_stats sn_stats_t;

struct n2n_sn
{
    time_t              start_time;     /* Used to measure uptime. */
    sn_stats_t          stats;
    int                 daemon;         /* If non-zero then daemonise. */
    uint16_t            lport;          /* Local UDP port to bind to. */
		uint16_t            mgmt_port;      /* Managing UDP ports */  
    SOCKET              sock;           /* Main socket for UDP traffic with edges. */
    SOCKET              sock6;
    SOCKET              mgmt_sock;      /* management socket. */
    struct peer_info *  edges;          /* Link list of registered edges. */
};

typedef struct n2n_sn n2n_sn_t;


static int try_forward( n2n_sn_t * sss,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize );

static int try_broadcast( n2n_sn_t * sss,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize );



/** Initialise the supernode structure */
static int init_sn( n2n_sn_t * sss )
{
#ifdef WIN32
    initWin32();
#endif
    memset( sss, 0, sizeof(n2n_sn_t) );

    sss->daemon = 1; /* By defult run as a daemon. */
    sss->lport = N2N_SN_LPORT_DEFAULT;
		sss->mgmt_port = N2N_SN_MGMT_PORT;
    sss->sock = -1;
    sss->sock6 = -1;
    sss->mgmt_sock = -1;
    sss->edges = NULL;

    return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *  it. */
static void deinit_sn( n2n_sn_t * sss )
{
    if (sss->sock >= 0)
    {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    if (sss->sock6 >= 0)
    {
        closesocket(sss->sock6);
    }
    sss->sock6 = -1;

    if ( sss->mgmt_sock >= 0 )
    {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock = -1;

    purge_peer_list( &(sss->edges), 0xffffffff );

#ifdef _WIN32
    WSACleanup();
#endif
}


/** Determine the appropriate lifetime for new registrations.
 *
 *  If the supernode has been put into a pre-shutdown phase then this lifetime
 *  should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime( n2n_sn_t * sss )
{
    return 120;
}


/** Update the edge table with the details of the edge which contacted the
 *  supernode. */
static int update_edge( n2n_sn_t * sss,
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        time_t now)
{
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    struct peer_info *  scan;

    traceEvent( TRACE_DEBUG, "update_edge for %s %s",
                macaddr_str( mac_buf, edgeMac ),
                sock_to_cstr( sockbuf, sender_sock ) );

    scan = find_peer_by_mac( sss->edges, edgeMac );

    if ( NULL == scan )
    {
        /* Not known */

        scan = (struct peer_info*)calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */

        memcpy(scan->community_name, community, sizeof(n2n_community_t) );
        memcpy(&(scan->mac_addr), edgeMac, sizeof(n2n_mac_t));
        memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));

        /* insert this guy at the head of the edges list */
        scan->next = sss->edges;     /* first in list */
        sss->edges = scan;           /* head of list points to new scan */

        traceEvent( TRACE_INFO, "update_edge created   %s ==> %s",
                    macaddr_str( mac_buf, edgeMac ),
                    sock_to_cstr( sockbuf, sender_sock ) );
    }
    else
    {
        /* Known */
        if ( (0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) ||
             (0 != sock_equal(sender_sock, &(scan->sock) )) )
        {
            memcpy(scan->community_name, community, sizeof(n2n_community_t) );
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));

            traceEvent( TRACE_INFO, "update_edge updated   %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }
        else
        {
            traceEvent( TRACE_DEBUG, "update_edge unchanged %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }

    }

    scan->last_seen = now;
    return 0;
}


/** Send a datagram to the destination embodied in a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock(n2n_sn_t * sss,
                           const n2n_sock_t * sock,
                           const uint8_t * pktbuf,
                           size_t pktsize)
{
    n2n_sock_str_t      sockbuf;

    if ( AF_INET == sock->family )
    {
        struct sockaddr_in udpsock;

        udpsock.sin_family = AF_INET;
        udpsock.sin_port = htons( sock->port );
        memcpy( &(udpsock.sin_addr), &(sock->addr.v4), IPV4_SIZE );

        traceEvent( TRACE_DEBUG, "sendto_sock %lu to %s",
                    pktsize,
                    sock_to_cstr( sockbuf, sock ) );

        return sendto( sss->sock, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in) );
    }
    else if ( AF_INET6 == sock->family )
    {
        struct sockaddr_in6 udpsock = { 0 };

        udpsock.sin6_family = AF_INET6;
        udpsock.sin6_port = htons( sock->port );
        memcpy( &(udpsock.sin6_addr), &(sock->addr.v6), IPV6_SIZE );

        traceEvent( TRACE_DEBUG, "sendto_sock6 %lu to %s",
                    pktsize,
                    sock_to_cstr( sockbuf, sock ) );

        return sendto( sss->sock6, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in6) );
    }
    else
    {
        errno = EAFNOSUPPORT;
        return -1;
    }
}



/** Try to forward a message to a unicast MAC. If the MAC is unknown then
 *  broadcast to all edges in the destination community.
 */
static int try_forward( n2n_sn_t * sss,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    scan = find_peer_by_mac( sss->edges, dstMac );

    if ( NULL != scan )
    {
        ssize_t data_sent_len;
        data_sent_len = sendto_sock( sss, &(scan->sock), pktbuf, pktsize );

        if ( data_sent_len == pktsize )
        {
            ++(sss->stats.fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr));
        }
        else
        {
            ++(sss->stats.errors);
#ifdef _WIN32
            DWORD err = WSAGetLastError();
            W32_ERROR(err, error);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %ls)",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       err, error );
            W32_ERROR_FREE(error);
#else
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno) );
#endif
        }
    }
    else
    {
        traceEvent( TRACE_DEBUG, "try_forward unknown MAC" );

        /* Not a known MAC so drop. */
    }

    return 0;
}


/** Try and broadcast a message to all edges in the community.
 *
 *  This will send the exact same datagram to zero or more edges registered to
 *  the supernode.
 */
static int try_broadcast( n2n_sn_t * sss,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    traceEvent( TRACE_DEBUG, "try_broadcast" );

    scan = sss->edges;
    while(scan != NULL)
    {
        if( 0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)) )
            && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) ) )
            /* REVISIT: exclude if the destination socket is where the packet came from. */
        {
            ssize_t data_sent_len;

            data_sent_len = sendto_sock(sss, &(scan->sock), pktbuf, pktsize);

            if(data_sent_len != pktsize)
            {
                ++(sss->stats.errors);
#ifdef _WIN32
                W32_ERROR(WSAGetLastError(), error);
                traceEvent(TRACE_WARNING, "multicast %lu to %s %s failed %ls",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str(mac_buf, scan->mac_addr),
                           error);
                W32_ERROR_FREE(error);
#else
                traceEvent(TRACE_WARNING, "multicast %lu to %s %s failed %s",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str(mac_buf, scan->mac_addr),
                           strerror(errno));
#endif
            }
            else
            {
                ++(sss->stats.broadcast);
                traceEvent(TRACE_DEBUG, "multicast %lu to %s %s",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str(mac_buf, scan->mac_addr));
            }
        }

        scan = scan->next;
    } /* while */

    return 0;
}


static int process_mgmt( n2n_sn_t * sss,
                         const struct sockaddr * sender_sock,
                         socklen_t sender_sock_len,
                         const uint8_t * mgmt_buf,
                         size_t mgmt_size,
                         time_t now)
{
    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize=0;
    ssize_t r;

    traceEvent( TRACE_DEBUG, "process_mgmt" );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "----------------\n" );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "uptime    %ld\n", (long) (now - sss->start_time) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "edges     %u\n",
			 (unsigned int)peer_list_size( sss->edges ) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "errors    %u\n",
			 (unsigned int)sss->stats.errors );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "reg_sup   %u\n",
			 (unsigned int)sss->stats.reg_super );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "reg_nak   %u\n",
			 (unsigned int)sss->stats.reg_super_nak );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "fwd       %u\n",
			 (unsigned int) sss->stats.fwd );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "broadcast %u\n",
			 (unsigned int) sss->stats.broadcast );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "last fwd  %lu sec ago\n",
			 (long unsigned int)(now - sss->stats.last_fwd) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "last reg  %lu sec ago\n",
			 (long unsigned int) (now - sss->stats.last_reg_super) );

    for (struct peer_info* list = sss->edges; list; list = list->next) {
        macstr_t buf0; n2n_sock_str_t buf1;
        ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize,
                         "%s %s %s\n",
                list->community_name,
                macaddr_str(buf0, list->mac_addr),
                sock_to_cstr(buf1, &list->sock) );
    }

    r = sendto( sss->mgmt_sock, resbuf, ressize, 0/*flags*/,
                sender_sock, sender_sock_len );

    if ( r <= 0 )
    {
        ++(sss->stats.errors);
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), error);
        traceEvent( TRACE_ERROR, "process_mgmt : sendto failed. %ls", error );
        W32_ERROR_FREE(error);
#else
        traceEvent( TRACE_ERROR, "process_mgmt : sendto failed. %s", strerror(errno) );
#endif
    }

    return 0;
}


/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp( n2n_sn_t * sss,
                        const struct sockaddr * sender_sock,
												socklen_t sender_sock_len,
                        const uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now)
{
    n2n_common_t        cmn; /* common fields in the packet header */
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    macstr_t            mac_buf;
    macstr_t            mac_buf2;
    n2n_sock_str_t      sockbuf;


    traceEvent( TRACE_DEBUG, "process_udp(%lu)", udp_size );

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if ( decode_common(&cmn, udp_buf, &rem, &idx) < 0 )
    {
        traceEvent( TRACE_ERROR, "Failed to decode common section" );
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */
    from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if ( cmn.ttl < 1 )
    {
        traceEvent( TRACE_WARNING, "Expired TTL" );
        return 0; /* Don't process further */
    }

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    if ( msg_type == MSG_TYPE_PACKET )
    {
        /* PACKET from one edge to another edge via supernode. */

        /* pkt will be modified in place and recoded to an output of potentially
         * different size due to addition of the socket.*/
        n2n_PACKET_t                    pkt;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */


        sss->stats.last_fwd=now;
        decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(pkt.dstMac) );

        traceEvent( TRACE_DEBUG, "Rx PACKET (%s) %s -> %s %s",
                    (unicast?"unicast":"multicast"),
                    macaddr_str( mac_buf, pkt.srcMac ),
                    macaddr_str( mac_buf2, pkt.dstMac ),
                    (from_supernode?"from sn":"local") );

        if ( !from_supernode )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            if (sender_sock->sa_family == AF_INET) {
                struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
                pkt.sock.family = AF_INET;
                pkt.sock.port = ntohs(sock->sin_port);
                memcpy( pkt.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
            } else if (sender_sock->sa_family == AF_INET6) {
                struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
                pkt.sock.family = AF_INET6;
                pkt.sock.port = ntohs(sock->sin6_port);
                memcpy( pkt.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
            }

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_PACKET( encbuf, &encx, &cmn2, &pkt );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            traceEvent( TRACE_DEBUG, "Rx PACKET fwd unmodified" );

            rec_buf = udp_buf;
            encx = udp_size;
        }

        /* Common section to forward the final product. */
        if ( unicast )
        {
            try_forward( sss, &cmn, pkt.dstMac, rec_buf, encx );
        }
        else
        {
            try_broadcast( sss, &cmn, pkt.srcMac, rec_buf, encx );
        }
    }/* MSG_TYPE_PACKET */
    else if ( msg_type == MSG_TYPE_REGISTER )
    {
        /* Forwarding a REGISTER from one edge to the next */

        n2n_REGISTER_t                  reg;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */

        sss->stats.last_fwd=now;
        decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(reg.dstMac) );

        if ( unicast )
        {
        traceEvent( TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                    macaddr_str( mac_buf, reg.srcMac ),
                    macaddr_str( mac_buf2, reg.dstMac ),
                    ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE)?"from sn":"local") );

        if ( 0 != (cmn.flags & N2N_FLAGS_FROM_SUPERNODE) )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            if (sender_sock->sa_family == AF_INET) {
                struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
                reg.sock.family = AF_INET;
                reg.sock.port = ntohs(sock->sin_port);
                memcpy( reg.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
            } else if (sender_sock->sa_family == AF_INET6) {
                struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
                reg.sock.family = AF_INET6;
                reg.sock.port = ntohs(sock->sin6_port);
                memcpy( reg.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
            }

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_REGISTER( encbuf, &encx, &cmn2, &reg );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            rec_buf = udp_buf;
            encx = udp_size;
        }

        try_forward( sss, &cmn, reg.dstMac, rec_buf, encx ); /* unicast only */
        }
        else
        {
            traceEvent( TRACE_ERROR, "Rx REGISTER with multicast destination" );
        }

    }
    else if ( msg_type == MSG_TYPE_REGISTER_ACK )
    {
        traceEvent( TRACE_DEBUG, "Rx REGISTER_ACK (NOT IMPLEMENTED) Should not be via supernode" );
    }
    else if ( msg_type == MSG_TYPE_REGISTER_SUPER )
    {
        n2n_REGISTER_SUPER_t            reg;
        n2n_REGISTER_SUPER_ACK_t        ack;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;

        /* Edge requesting registration with us.  */

        sss->stats.last_reg_super=now;
        ++(sss->stats.reg_super);
        decode_REGISTER_SUPER( &reg, &cmn, udp_buf, &rem, &idx );

        cmn2.ttl = N2N_DEFAULT_TTL;
        cmn2.pc = n2n_register_super_ack;
        cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
        memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );

        memcpy( &(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t) );
        memcpy( ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t) );
        ack.lifetime = reg_lifetime( sss );

        if (sender_sock->sa_family == AF_INET) {
            struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
            ack.sock.family = AF_INET;
            ack.sock.port = ntohs(sock->sin_port);
            memcpy( ack.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
        } else if (sender_sock->sa_family == AF_INET6) {
            struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
            ack.sock.family = AF_INET6;
            ack.sock.port = ntohs(sock->sin6_port);
            memcpy( ack.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
        }

        ack.num_sn=0; /* No backup */
        memset( &(ack.sn_bak), 0, sizeof(n2n_sock_t) );

        traceEvent( TRACE_DEBUG, "Rx REGISTER_SUPER for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        update_edge( sss, reg.edgeMac, cmn.community, &(ack.sock), now );

        encode_REGISTER_SUPER_ACK( ackbuf, &encx, &cmn2, &ack );

        sendto( sss->sock, ackbuf, encx, 0,
                (struct sockaddr *)sender_sock, sizeof(struct sockaddr_in) );

        traceEvent( TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

    }


    return 0;
}


/** Help message to print if the command line arguments are not valid. */
static void help(int argc, char * const argv[])
{
    fprintf( stderr, "%s usage\n", argv[0] );
    fprintf( stderr, "-l <lport>\tSet UDP main listen port to <lport>\n" );
    fprintf( stderr, "-4        \tUse IPv4 network (default)\n" );
    fprintf( stderr, "-6        \tUse IPv6 network\n" );
#ifndef _WIN32
    fprintf( stderr, "-t <port>\tSet management UDP port to <port> (default = 5645)\n" );
#endif
#if defined(N2N_HAVE_DAEMON)
    fprintf( stderr, "-f        \tRun in foreground.\n" );
#endif /* #if defined(N2N_HAVE_DAEMON) */
    fprintf( stderr, "-v        \tIncrease verbosity. Can be used multiple times.\n" );
    fprintf( stderr, "-h        \tThis help message.\n" );
    fprintf( stderr, "\n" );
}

static int run_loop( n2n_sn_t * sss );

/* *********************************************** */

static const struct option long_options[] = {
  { "foreground",      no_argument,       NULL, 'f' },
  { "local-port",      required_argument, NULL, 'l' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { "ipv4",            no_argument,       NULL, '4' },
  { "ipv6",            no_argument,       NULL, '6' },
  { NULL,              0,                 NULL,  0  }
};

/** Main program entry point from kernel. */
int main( int argc, char * const argv[] )
{
    n2n_sn_t sss;
    bool ipv4 = false, ipv6 = false;

#ifndef _WIN32
    /* stdout is connected to journald, so don't print data/time */
    if ( getenv( "JOURNAL_STREAM" ) )
        useSystemd = true;
#endif

#if _WIN32
    SetConsoleOutputCP(65001);

    if (scm_startup(L"supernode") == 1) {
        /* supernode is running as a service, so quit */
        return 0;
    }

    if ( !IsWindows7OrGreater() ) {
        traceEvent( TRACE_ERROR, "This Windows Version is not supported. Windows 7 or newer is required." );
        return 1;
    }
#endif

    init_sn( &sss );

    {
        int opt;

        while((opt = getopt_long(argc, argv, "ft:l:46vh", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'l': /* local-port */
                sss.lport = atoi(optarg);
                break;
            case 't':
#ifndef _WIN32
						sss.mgmt_port = atoi(optarg);  
						if (sss.mgmt_port == 0) {  
								traceEvent(TRACE_ERROR, "Invalid management port: %s", optarg);  
								exit(-1);  
						}  
#endif
                break;
            case 'f': /* foreground */
                sss.daemon = 0;
                break;
            case '4':
                ipv4 = true;
                break;
            case '6':
                ipv6 = true;
                break;
            case 'h': /* help */
                help(argc, argv);
                exit(0);
            case 'v': /* verbose */
                ++traceLevel;
                break;
            }
        }

    }

    /* enable ipv4 if there was no parameter provided */
    ipv4 = ipv4 || !ipv6;

#if defined(N2N_HAVE_DAEMON)
    if (sss.daemon)
    {
        useSyslog = true; /* traceEvent output now goes to syslog. */
        if ( -1 == daemon( 0, 0 ) )
        {
            traceEvent( TRACE_ERROR, "Failed to become daemon." );
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    traceEvent( TRACE_DEBUG, "traceLevel is %d", traceLevel);

    if (ipv4) {
        sss.sock = open_socket(sss.lport, 1 /*bind ANY*/ );
        if ( -1 == sss.sock )
        {
#ifdef _WIN32
            W32_ERROR(WSAGetLastError(), error);
            traceEvent( TRACE_ERROR, "Failed to open main IPv4 socket. %ls", error );
            W32_ERROR_FREE(error);
#else
            traceEvent( TRACE_ERROR, "Failed to open main IPv4 socket. %s", strerror(errno) );
#endif
            exit(-2);
        }
        else
        {
            traceEvent( TRACE_NORMAL, "supernode is listening on UDP4 %u (main)", sss.lport );
        }
    }
    if (ipv6) {
        sss.sock6 = open_socket6(sss.lport, 1 /*bind ANY*/ );
        if ( -1 == sss.sock6 )
        {
#ifdef _WIN32
            W32_ERROR(WSAGetLastError(), error);
            traceEvent( TRACE_ERROR, "Failed to open main IPv6 socket. %ls", error );
            W32_ERROR_FREE(error);
#else
            traceEvent( TRACE_ERROR, "Failed to open main IPv6 socket. %s", strerror(errno) );
#endif
            exit(-2);
        }
        else
        {
            traceEvent( TRACE_NORMAL, "supernode is listening on UDP6 %u (main)", sss.lport );
        }
    }

#ifndef _WIN32
        sss.mgmt_sock = open_socket(sss.mgmt_port, 0 /* bind LOOPBACK */ );
#endif // _WIN32
    if ( -1 == sss.mgmt_sock )
    {
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), error);
        traceEvent( TRACE_ERROR, "Failed to open management socket. %ls", error );
        W32_ERROR_FREE(error);
#else
        traceEvent( TRACE_ERROR, "Failed to open management socket. %s", strerror(errno) );
#endif
        exit(-2);
    }
#ifndef _WIN32
        traceEvent( TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss.mgmt_port );
#endif // _WIN32
    traceEvent(TRACE_NORMAL, "supernode started");

    return run_loop(&sss);
}

/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int run_loop( n2n_sn_t * sss )
{
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    int keep_running=1;

    sss->start_time = time(NULL);

    while(keep_running)
    {
        int rc;
        ssize_t bread;
        struct pollfd fds[3];
        int nfds = 0;
        time_t now=0;

        if (sss->sock != -1) {
            fds[nfds].fd = sss->sock;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        if (sss->sock6 != -1) {
            fds[nfds].fd = sss->sock6;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        fds[nfds].fd = sss->mgmt_sock;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        nfds++;

        rc = poll(fds, nfds, 10000); /* 10-second timeout */

        now = time(NULL);

        if(rc > 0)
        {
            int idx = 0;

            if (sss->sock != -1) {
                if (fds[idx].revents & POLLIN) {
                    struct sockaddr_storage udp_sender_sock;
                    socklen_t udp_sender_len = sizeof(udp_sender_sock);

                    bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                                   (struct sockaddr *)&udp_sender_sock, &udp_sender_len);

                    if (bread > 0) {
												process_udp( sss, (struct sockaddr*) &udp_sender_sock, udp_sender_len,
																			pktbuf, bread, now );
                    }
                }
                idx++;
            }

            if (sss->sock6 != -1) {
                if (fds[idx].revents & POLLIN) {
                    struct sockaddr_storage udp6_sender_sock;
                    socklen_t udp6_sender_len = sizeof(udp6_sender_sock);

                    bread = recvfrom(sss->sock6, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                                   (struct sockaddr *)&udp6_sender_sock, &udp6_sender_len);

                    if (bread > 0) {
												process_udp( sss, (struct sockaddr*) &udp6_sender_sock, udp6_sender_len,
																			pktbuf, bread, now );
                    }
                }
                idx++;
            }

            if (fds[idx].revents & POLLIN) {
                struct sockaddr_storage mgmt_sender_sock;
                socklen_t mgmt_sender_len = sizeof(mgmt_sender_sock);

                bread = recvfrom(sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&mgmt_sender_sock, &mgmt_sender_len);

                if (bread > 0) {
                    process_mgmt(sss, (struct sockaddr*)&mgmt_sender_sock,
                               mgmt_sender_len, pktbuf, bread, now);
                }
            }
        }
        else
        {
            traceEvent( TRACE_DEBUG, "timeout" );
        }

        purge_expired_registrations( &(sss->edges) );
    }

    deinit_sn( sss );
    return 0;
}
