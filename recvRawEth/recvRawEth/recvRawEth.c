/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define DEST_MAC0	0xb8
#define DEST_MAC1	0x27
#define DEST_MAC2	0xeb
#define DEST_MAC3	0x2f
#define DEST_MAC4	0xec
#define DEST_MAC5	0x56

#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"eth1"
#define BUF_SIZ		1024

int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	char receiver[INET6_ADDRSTRLEN];
	int sockfd, ret, i, j;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage source_addr, dest_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ - 1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ - 1) == -1) {
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	for (j = 0; j < 100; j++)
	{
	
		// printf("listener: Waiting to recvfrom...\n");
		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
		// printf("listener: got packet %zd bytes\n", numbytes);

//		/* Check the packet is for me */
//		if (eh->ether_dhost[0] == DEST_MAC0 &&
//				eh->ether_dhost[1] == DEST_MAC1 &&
//				eh->ether_dhost[2] == DEST_MAC2 &&
//				eh->ether_dhost[3] == DEST_MAC3 &&
//				eh->ether_dhost[4] == DEST_MAC4 &&
//				eh->ether_dhost[5] == DEST_MAC5) {
//			printf("Correct destination MAC address\n");
//		}
//		else {
//			printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
//				eh->ether_dhost[0],
//				eh->ether_dhost[1],
//				eh->ether_dhost[2],
//				eh->ether_dhost[3],
//				eh->ether_dhost[4],
//				eh->ether_dhost[5]);
//			ret = -1;
//			continue;
//		}

		/* Get source IP */
		((struct sockaddr_in *)&source_addr)->sin_addr.s_addr = iph->saddr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)&source_addr)->sin_addr, sender, sizeof sender);

		((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = iph->daddr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)&dest_addr)->sin_addr, receiver, sizeof receiver);

		/* Look up my device IP addr if possible */
		strncpy(if_ip.ifr_name, ifName, IFNAMSIZ - 1);
	
		if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) {
			/* if we can't check then don't */
			printf("src %s, dst %s, nic %s\n",
				sender, 
				receiver,
				inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
		
			/* ignore if I sent it */
			if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0) {
				printf("but I sent it :(\n");
				ret = -1;
				continue;
			}
		}

		/* UDP payload length */
		ret = ntohs(udph->len) - sizeof(struct udphdr);

		/* Print packet */
//		printf("\tData:");
//		for (i = 0; i < numbytes; i++) 
//			printf("%02x:", buf[i]);
//	
//		printf("\n");
	}
	
	close(sockfd);
	return ret;
}