/*
 *  mySniffer.h
 *  cns_hw0_psniff
 *
 *  Created by puyan on Mon Aug 23 2004.
 *  This is pretty much just structs from 
 *  tcpdump.org to keep the sniffer platform
 *  independent. I had to fix some terrible 
 *  errors to get endians to not screw up on
 *  big endian architectures like PPC and Sparc. 
 *
 */
 
 
 #ifdef LINUX
 typedef u_int32_t tcp_seq; 
 #endif

 
 
/* this holds info on where to sniff from */

typedef struct _mailFields 
{

	char *from;
	char *to;
	char *srcIp;
	char *destIp;
	char *com;
	char *virus;


}mailFields;

#ifdef MEDIUM
typedef struct _sniffMedium
{

	char *dev;
	char *port;
	char *file;

}sniffMedium;
#endif 
 
/* Ethernet header */
struct etherHeader {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ipHeader {
		 #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   ip_hl:4,        /* header length */
                        ip_v:4;         /* version */
		#endif /* not _IP_VHL */
			   
		 #if BYTE_ORDER == BIG_ENDIAN
                u_int   ip_v:4,         /* version */
                        ip_hl:4;        /* header length */
        #endif

		
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* TCP header */
struct tcpHeader {
        u_short th_sport;                       /* source port */
        u_short th_dport;                       /* destination port */
        tcp_seq th_seq;                         /* sequence number */
        tcp_seq th_ack;                         /* acknowledgement number */
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   th_x2:4,                /* (unused) */
                        th_off:4;               /* data offset */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   th_off:4,               /* data offset */
                        th_x2:4;                /* (unused) */
        #endif
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                         /* window */
        u_short th_sum;                         /* checksum */
        u_short th_urp;                         /* urgent pointer */
};




void sniff_packets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
