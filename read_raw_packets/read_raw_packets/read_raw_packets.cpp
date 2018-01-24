#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std;

// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt

int main(int argc, char *argv[])
{
	int err;
	
	int sockId = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockId < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}
	
	struct ifreq ifr;
	strncpy((char *) ifr.ifr_name, "eth1", IFNAMSIZ);
	err = ioctl(sockId, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		perror("SIOCGIFINDEX");
		return EXIT_FAILURE;
	}
	
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	// sll.sll_protocol = htons(ETH_P_IP);
	err = bind(sockId, (struct sockaddr *) &sll, sizeof(sll));
	if (err < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}

	struct packet_mreq      mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	err = setsockopt(sockId, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	if (err < 0) {
		perror("PACKET_ADD_MEMBERSHIP");
		return EXIT_FAILURE;
	}

	char buf[1600];
	
	//	struct ethhdr  *eth;
	//	eth = (struct ethhdr*) buf;
	//	memcpy(eth->h_dest, dest_mac, ETH_ALEN);
	//	memcpy(eth->h_source, src_mac, ETH_ALEN); 
	//	eth->h_proto = ETH_P_IP;

	//	struct iphdr *ip =  (struct iphdr*)(eth + 1);

	struct ethhdr  *eth;
	struct iphdr   *iph;
	unsigned short iphdrlen;
		
	for (int i = 0; i < 100; i++)
	{
		ssize_t bytes_read = read(sockId, (unsigned char *) &buf, 1600);
		if (bytes_read < 0) {
			perror("Error during read");
			perror("PACKET_ADD_MEMBERSHIP");
			return EXIT_FAILURE;
		}
		
		eth = (struct ethhdr *)buf;
		iph = (struct iphdr *)(buf  + sizeof(struct ethhdr));
		iphdrlen = iph->ihl * 4;

		struct in_addr s1, s2, s3;
			
		s1.s_addr = iph->saddr;
		s2.s_addr = iph->daddr;
		s3.s_addr = 0;  // m_stb_data->group_ip;
			
		char ss1[255];
		char ss2[255];
		char ss3[255];

		strcpy(ss1, inet_ntoa(s1));
		strcpy(ss2, inet_ntoa(s2));
		strcpy(ss3, inet_ntoa(s3));
			
		printf("bytes %d src %-15s dst %-15s grp %-15s\n", bytes_read, ss1, ss2, ss3);		
	}
	
	close(sockId);
	
	printf
		("Done\n");
}
