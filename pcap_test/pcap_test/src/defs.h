#ifndef DEFS_H
#define DEFS_H

	
#include <pcap.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen

#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>       //Provides declarations for udp header
#include<netinet/tcp.h>       //Provides declarations for tcp header
#include<netinet/ip.h>        //Provides declarations for ip header
#include<netinet/in.h>
#include<netinet/igmp.h>
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include<linux/if.h>
#include<net/ethernet.h>      //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<inttypes.h>

#endif