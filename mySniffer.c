#include "mySniffer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Puyan Lotfi gtg945h */

#define _BSD_SOURCE 1
#define NUM_PACKETS -1 /* negative means go until error*/
#define MS_DELAY 1     /* gives me what is on the line every 1 ms */
#define ATTACH_FIELD_SIZE 32

static int vscan = 0;

int main(int argc, char *argv[]) {

  /**********     Variable Declaration.     **********/

  int medium_selected = 0;

  int port_selected = 0;

  int c = 0; /* This is used for the getopting */

  pcap_t *sessionHandle = NULL; /* The Pcap Session Handle */

  char *deviceEther = NULL; /* Device To Sniff On. */

  char errorBuffer[PCAP_ERRBUF_SIZE]; /* Error Buffer. */

  char *fileName = NULL; /* Name of pcap file to sniff from */

  struct bpf_program filter; /* The Compiled Filter Expression. */

  char *filter_app = ""; /* The Filter Expression */

  bpf_u_int32 netmask; /* The Netmask Of Our Sniffing Device. */

  bpf_u_int32 ipOfDeviceEther; /* The IP Of Our Sniffing Device. */

  opterr = 0;

  while ((c = getopt(argc, argv, "vd:p:f:")) != -1) {
    switch (c) {
    case 'v':
      vscan = 1;
      break;

    case 'd':
      deviceEther = optarg;
      medium_selected = 1;
      break;

    case 'p':
      filter_app = optarg;
      port_selected = 0;
      break;

    case 'f':
      fileName = optarg;
      medium_selected = 1;
      break;

    case '?':
      printf("Format is: sniffer [-v] [-d device] "
             "[-p \"port #\"] [-f filename]\n");
      return 1;

    default:
      printf("This should never happen!\n");
      break;
    }
  }

  if (medium_selected) {
    printf("No device or file medium "
           "selected! Will default to device"
           "autoselect on port 25.\n");
  }

  /**********     Funtion Calls.     **********/

  if (NULL == deviceEther) {
    printf("Not A Valid Ethernet Device... "
           "Asigning One Automaticaly...\t");

    deviceEther = pcap_lookupdev(errorBuffer);

    printf("%s found.\n", deviceEther);
  }

  if (NULL != fileName) {
    printf("Sniffing on pcap file %s\n", fileName);

    if (NULL == (sessionHandle = pcap_open_offline(fileName, errorBuffer))) {
      printf("pcap_open_offline(): %s\n", errorBuffer);
      exit(1);
    }

    printf("Sniffing on pcap file %s on ", fileName);
  } else {

    printf("You should be root, administrator, su, or "
           "sudo!\n... or chmod 777 /dev/bpf* if you "
           "are a BSD user (Just kidding, don't do this ;) ).\n\n");

    /* Properties Of The Ethernet Device. */
    pcap_lookupnet(deviceEther, &ipOfDeviceEther, &netmask, errorBuffer);

    printf("Using %s as ethernet device.\n", deviceEther);

    /* Open The Packet Sniffing Session In Promiscuous Mode. */
    /* This is also where ms is defined*/
    if (NULL == (sessionHandle = pcap_open_live(deviceEther, BUFSIZ, 1,
                                                MS_DELAY, errorBuffer))) {
      printf("pcap_open_live(): %s\n", errorBuffer);
      exit(1);
    }

    printf("Sniffing on network interface %s on ", deviceEther);
  }

  /* Compile The Filter So That The Content Of A Specific Port May Be Sniffed
   * Only. */
  /* if(-1 == pcap_compile(sessionHandle, &filter, filter_app, 0, 0xFFFFFF00))
   */
  if (-1 ==
      pcap_compile(sessionHandle, &filter, filter_app, 0, ipOfDeviceEther)) {
    printf("pcap_compile died... \n");
    exit(1);
  }

  printf("%s...\n", filter_app);

  /* Run The Filter. */
  if (-1 == pcap_setfilter(sessionHandle, &filter)) {
    printf("pcap_setfilter died...\n");
    exit(1);
  }

  /* This Is Our Callback Function. */
  pcap_loop(sessionHandle, NUM_PACKETS, sniff_packets, NULL);

  /* Close Session. */
  pcap_close(sessionHandle);

  printf("\n\nFIN\n");
  return (0);
}

void sniff_packets(u_char *args, const struct pcap_pkthdr *header,
                   const u_char *packet) {

  /* Define pointers for packet's attributes */
  const struct etherHeader *ether; /* The ethernet header */
  const struct ipHeader *ip;       /* The IP header */
  const struct tcpHeader *tcp;     /* The TCP header */
  u_char *payload;                 /* Packet payload, was a const char * */
  int size_ethernet;
  int size_ip;
  int size_tcp;
  int size_payload;
  char *paybuf;

  static mailFields email_data;
  static const char *attachField = "Content-Disposition: attachment;";
  static const char *virusFile = "eicar.com";
  static const char *virusString =
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  char testBuffer[100];
  static const char characterRef[] = {'C', 'E', 'X'};

  size_ethernet = sizeof(struct etherHeader);

  ether = (struct etherHeader *)(packet);
  ip = (struct ipHeader *)(packet + size_ethernet);

  size_ip = ip->ip_hl * 4;

#ifdef DEBUG
  printf("Size of IP header: %d\n", size_ip);
#endif

  tcp = (struct tcpHeader *)(packet + size_ethernet + size_ip);

  size_tcp = tcp->th_off * 4;

#ifdef DEBUG
  printf("Size of TCP header: %d\n", size_tcp);
#endif

  payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);

  size_payload = (ntohs(ip->ip_len) - size_ip - size_tcp);

#ifdef DEBUG
  printf("Size of payload: %d\n", size_payload);
#endif

  if (NULL == (paybuf = malloc((size_payload * sizeof(char)) + 1))) {
#ifdef DEBUG
    fprintf(stderr, "\n\n!!!|[~~~Malloc Failed~~~]|!!!\n\n");
#endif

    return;
  }

  snprintf(paybuf, size_payload, "%s", payload);
  /*paybuf[size_payload] = '\0';*/

#ifdef DEBUG
  if ('\0' == paybuf[size_payload])
    printf("YEEEEEEEEEEEEEEEHAAAAAAAAAWWWWWWWWWWWW!!!!!!!!!!!!!!!!!!!!!!\n\n");
#endif

#ifdef DEBUG
  printf("Payload:\n%s\n", paybuf);
#endif

  if (!vscan)
    printf("%s", paybuf);
  else {

#ifdef DEBUG
    printf("hello\n\n");
#endif

    if ('E' == paybuf[0] && 'H' == paybuf[1] && 'L' == paybuf[2] &&
        'O' == paybuf[3]) {

      email_data.from = NULL;
      email_data.to = NULL;
      email_data.srcIp = NULL;
      email_data.destIp = NULL;

      return;
    }

    else if ('M' == paybuf[0] && 'A' == paybuf[1] && 'I' == paybuf[2] &&
             'L' == paybuf[3]) {

      email_data.from = paybuf + 11;

      return;
    }

    else if ('R' == paybuf[0] && 'C' == paybuf[1] && 'P' == paybuf[2] &&
             'T' == paybuf[3]) {

      email_data.to = paybuf + 9;

      return;
    }

    else {

      int i = 0;
      int j = 0;

      while ('\0' != paybuf[i]) {

        if (3 <= j) {

          printf("J TOO BIG!!!!!!!");

          exit(0);
        }

        if (paybuf[i] == characterRef[j] ||
            paybuf[i] == (characterRef[j] + ('e' - 'E'))) {
          if (0 == j) {
            snprintf(testBuffer, 33, "%s", paybuf + i);

#ifdef DEBUG
            printf("%s\n\n", testBuffer);
#endif

            if (0 == strcmp(testBuffer, attachField) ||
                testBuffer[32] == attachField[32]) {
#ifdef DEBUG
              printf("Found attach field\n\n\n");
#endif

              j++;
            }
          }

          if (1 == j) {
            snprintf(testBuffer, 10, "%s", paybuf + i);

            if (0 == strcasecmp(testBuffer, virusFile)) {

              email_data.com = (char *)virusFile;

              j++;
            }
          }

          if (2 == j) {
            snprintf(testBuffer, 69, "%s", paybuf + i);

            if (0 == strcmp(testBuffer, virusString)) {

              /** keep in mind all fields in email_data
               are just pointers!!! */

              email_data.virus = (char *)testBuffer;

              email_data.from[23] = '\0';
              email_data.to[22] = '\0';

              printf("\x07Virus reported! \nFrom: %s\nTo: %s\nFi"
                     "lename: %s\nContent: %s\n\n"
                     "Proceeding to clean... \n\n"
                     "CLEANED!\n\n",
                     email_data.from, email_data.to, email_data.com,
                     email_data.virus);

              break;
            }
          }
        }

        i++;
      }
    }
  }

#ifdef DEBUG
  printf("Freeing paybuf\n");
#endif

  free(paybuf);

#ifdef DEBUG
  printf("paybuf freed\n");
#endif
}
