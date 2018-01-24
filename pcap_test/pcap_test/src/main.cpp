// https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/

#include <getopt.h>

#include "tools.h"
#include "defs.h"
#include "pim.h"
#include "igmp.h"

#define PACKAGE_VERSION "1.0.8"
#define MAX_DATA_WAIT_MS 60 * 1000

char timestamp[255];
char ip_address_parm[INET_ADDRSTRLEN];
char if_name_parm[32];
bool debug_enabled = false;

uint32_t ip_address;
uint32_t group_ip;
uint16_t m_port = 7399;

bool got_membership_report = false;
bool got_data = false;
bool wait_for_change = false;

cTimeMs *m_dataTimer = new cTimeMs();
cTimeMs *m_timeoutTimer = new cTimeMs();

struct in_addr s1, s2, s3, s4;

char ss1[255];
char ss2[255];
char ss3[255];
char ss4[255];

struct iphdr *iph;
int iphdrlen;

char *prognm      = NULL;

void handle_group_report(in_addr_t group);

static char *progname(char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = arg0;

	return nm;
}

void usage()
{
	printf("Usage: %s [-indv]\n", prognm);
	printf("  -i  --address=IP_ADDRESS    ip address to listen\n");
	printf("  -n  --nic=NETWORK_IF        network interface name - default ANY\n");
	printf("  -d  --debug                 enable debug output\n");
	printf("  -v, --version               Show version\n");
	printf("  -?, --help                  This message\n");
	printf("\n");
	
	exit(0);
}

void process_pim_join_prune(char *pim) {
	
	uint8_t *data = (uint8_t *)(pim + sizeof(pim_t));
	uint8_t *data_start;
	
	pim_encod_uni_addr_t eutaddr;
	uint8_t num_groups;
	uint16_t holdtime;
	uint8_t reserved;
	size_t len;

	uint32_t group, source;
	uint16_t num_j_srcs;
	uint16_t num_p_srcs;

	pim_encod_grp_addr_t encod_group;
	pim_encod_src_addr_t encod_src;
	
	GET_EUADDR(&eutaddr, data);
	GET_BYTE(reserved, data);
	GET_BYTE(num_groups, data);
	GET_HOSTSHORT(holdtime, data);
	
	if (num_groups == 0) 
		return;

	s1.s_addr = iph->saddr;
	s2.s_addr = iph->daddr;
	
	strcpy(ss1, inet_ntoa(s1));
	strcpy(ss2, inet_ntoa(s2));
	
	GetTimestamp((char *) &timestamp);	

	while (num_groups--) {
		size_t srclen;

		GET_EGADDR(&encod_group, data);
		GET_HOSTSHORT(num_j_srcs, data);
		GET_HOSTSHORT(num_p_srcs, data);
		
		group = encod_group.mcast_addr;
		
		// process joins
		while(num_j_srcs--) {
			GET_ESADDR(&encod_src, data);
			source = encod_src.src_addr;
			
			handle_group_report(group);
			
			if (debug_enabled)
			{
				s3.s_addr = source;
				s4.s_addr = group;
			
				strcpy(ss3, inet_ntoa(s3));
				strcpy(ss4, inet_ntoa(s4));

				printf("%s %-11s src %-15s dst %-15s Join: src %-15s grp %-15s\n", timestamp, "IP:", ss1, ss2, ss3, ss4);
			}
		}
		
		// process prunes
		while(num_p_srcs--) {
			GET_ESADDR(&encod_src, data);
			source = encod_src.src_addr;
			
			if (debug_enabled)
			{
				s3.s_addr = source;
				s4.s_addr = group;
			
				strcpy(ss3, inet_ntoa(s3));
				strcpy(ss4, inet_ntoa(s4));

				printf("%s %-11s src %-15s dst %-15s Leave: src %-15s grp %-15s\n", timestamp, "IP:", ss1, ss2, ss3, ss4);
			}
		}
	}
}

void handle_group_report(in_addr_t group)
{
	if ((got_membership_report) && (iph->saddr == ip_address) && (group_ip == group) && (group_ip != 0))
		return;
	
	if (!debug_enabled)
	{
		if (iph->saddr != ip_address)
			return;
	}
	
	if (debug_enabled)
	{
		s3.s_addr = group;
		strcpy(ss3, inet_ntoa(s3));
		
		printf("%s IGMP_V2_MEMBERSHIP_REPORT: src %-15s dst %-15s grp %-15s %s\n", timestamp, ss1, ss2, ss3, iph->saddr == ip_address ? "OK" : "");
	}
	
	if (iph->saddr == ip_address)
	{
		if ((group_ip == 0) || (group_ip != group))
		{
			s3.s_addr = group;
			strcpy(ss3, inet_ntoa(s3));

			printf("%s %-11s src %-15s dst %-15s grp %-15s\n", timestamp, "Join:", ss1, ss2, ss3);

			got_data = false;
			got_membership_report = true;
			group_ip = group;

			if (!wait_for_change)
				printf("%s %-11s src %-15s dst %-15s grp %-15s Elapsed %" PRIu64 "\n", timestamp, "Lost:", ss1, ss2, ss3, m_dataTimer->Elapsed());
			
			wait_for_change = false;

			m_dataTimer->Set();
			m_timeoutTimer->Set(MAX_DATA_WAIT_MS);		
		}
	}
}

void process_igmp(const u_char *packet)
{
	struct igmp *igmp = (struct igmp *)(packet + iphdrlen  +  sizeof(struct ethhdr));
	
	struct igmpv3_report *report;
	struct igmpv3_grec *record;
	struct in_addr  rec_group;
	int num_groups, rec_type;
	int             rec_auxdatalen;
	int             rec_num_sources;
	int             record_size = 0;

	GetTimestamp((char *) &timestamp);			

	switch (igmp->igmp_type)
	{
	case IGMP_MEMBERSHIP_QUERY:
		// printf("%s IGMP_MEMBERSHIP_QUERY: src %-15s dst %-15s\n", timestamp, ss1, ss2);
		break;
		
	case IGMP_V2_MEMBERSHIP_REPORT:
		handle_group_report(igmp->igmp_group.s_addr);
		break;
		
	case IGMP_V3_MEMBERSHIP_REPORT:
		report = (struct igmpv3_report *) igmp;
		num_groups = ntohs(report->ngrec);

		record = &report->grec[0];
		rec_type = record->grec_type;
		rec_group.s_addr = (in_addr_t)record->grec_mca;

		rec_num_sources = ntohs(record->grec_nsrcs);
		rec_auxdatalen = record->grec_auxwords;
		record_size = sizeof(struct igmpv3_grec) + sizeof(uint32_t) * rec_num_sources + rec_auxdatalen;

		//		if (debug_enabled)
		//			printf("%s IGMP_V3_MEMBERSHIP_REPORT: src %-15s dst %-15s groups %d\n", timestamp, ss1, ss2, num_groups);
		
				for(int i = 0 ; i < num_groups ; i++)
		{
			switch (rec_type) {
			case IGMP_MODE_IS_EXCLUDE:
			case IGMP_CHANGE_TO_EXCLUDE_MODE:
				handle_group_report(rec_group.s_addr);
				break;
			
			case IGMP_ALLOW_NEW_SOURCES: // new sources
			break;
			
			case IGMP_CHANGE_TO_INCLUDE_MODE: // new sources
			break;
			
			case IGMP_BLOCK_OLD_SOURCES:
				// printf("%s IGMP_BLOCK_OLD_SOURCES (Leave): src %-15s dst %-15s\n", timestamp, ss1, ss2);
				break;
			
			default:
				printf("IGMP: Unknown record type %d\n", rec_type);
				break;
			}
			
			record = (struct igmpv3_grec *)((uint8_t *)record + record_size);
		}
		
		break;
			
	case IGMP_V2_LEAVE_GROUP:
		if (debug_enabled)
			printf("%s IGMP_V2_LEAVE_GROUP: src %-15s dst %-15s\n", timestamp, ss1, ss2);
		break;

	default:
		printf("Unknown IGMP Type: %d\n", igmp->igmp_type);
		return;
	}
}	

void process_udp(const u_char *packet)
{
	uint16_t source_port, dest_port;
	
	if (!got_membership_report || got_data)
		return;
	
	struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
    
	source_port = ntohs(udph->source);
	dest_port = ntohs(udph->dest);
    
	if ((iph->daddr == group_ip) && (dest_port == m_port))
		got_data = true;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	pim_t *pim_hdr = (struct pim_t *)(packet + iphdrlen + sizeof(struct ethhdr));
	
	s1.s_addr = iph->saddr;
	s2.s_addr = iph->daddr;
			
	strcpy(ss1, inet_ntoa(s1));
	strcpy(ss2, inet_ntoa(s2));
			
	switch (iph->protocol) //Check the Protocol and do accordingly...
		{
		case 1:  //ICMP Protocol
			// printf("ProcessPacket: ICMP Protocol\n");
			break;
        
		case 2:  //IGMP Protocol
		    // result = handle_igmp(buffer, size);
			process_igmp(packet);
			break;
        
		case 6:  //TCP Protocol
		    // result = handle_tcp_packet(buffer, size);
			break;
        
		case 17: //UDP Protocol
			process_udp(packet);
			// result = handle_udp(buffer, size);
			break;
	
		case 38:
			break;
		
		case 89: // OSPFIGP Protocol
			// printf("ProcessPacket: Protocol Protocol\n");
			break;
			
		case 103: // PIM Protocol
			// result = handle_pim(buffer, size);
			// GetTimestamp((char *) &timestamp);	
			// printf("%s PIM: type %d src %-15s dst %-15s\n", timestamp, pim_hdr->pim_type, ss1, ss2);
		
			if(pim_hdr->pim_type == 3) // PIM_JOIN_PRUNE
				process_pim_join_prune((char *) pim_hdr);
		
			break;

		case 118: // STP Protocol
			// result = handle_pim(buffer, size);
			break;

		case 128:
			break;
		
		case 207:
			break;
		
		case 226: // Unassigned
			// result = handle_pim(buffer, size);
			break;

		default: //Some Other Protocol like ARP etc.
			printf("callback: Uknown IP Protocol %d\n", iph->protocol);
			break;
		}	
	
	// printf("Packet number [%d], length of this packet is: %d\n", count++, pkthdr->len);
	
	if(got_data && got_membership_report)
	{
		s3.s_addr = group_ip;
		strcpy(ss3, inet_ntoa(s3));

		GetTimestamp((char *) &timestamp);	
		printf("%s %-11s src %-15s dst %-15s grp %-15s Elapsed %" PRIu64 "\n", timestamp, "Data:", ss1, ss2, ss3, m_dataTimer->Elapsed());

		wait_for_change = true;
		got_membership_report = false;
		got_data = false;
	}
	
	if (got_membership_report && m_timeoutTimer->TimedOut())
	{
		s3.s_addr = group_ip;
		strcpy(ss3, inet_ntoa(s3));

		GetTimestamp((char *) &timestamp);	
		printf("%s %-11s src %-15s dst %-15s grp %-15s Elapsed %" PRIu64 "\n", timestamp, "Timeout", ss1, ss2, ss3, m_dataTimer->Elapsed());
		
		got_membership_report = false;
		got_data = false;
		wait_for_change = false;
	}
	
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp; /* to hold compiled program */
	bpf_u_int32 pMask; /* subnet mask */
	bpf_u_int32 pNet; /* ip address*/

	struct option long_options[] = {
		{ "address", 1, 0, 'i' },
		{ "nic", 1, 0, 'n' },
		{ "debug", 0, 0, 'd' },
		{ "version", 0, 0, 'v' },
		{ "help", 0, 0, '?' },
		{ NULL, 0, 0, 0 }
	};

	char versionstring[100];
	int   ch;
	
	prognm = progname(argv[0]);
	snprintf(versionstring, sizeof(versionstring), "%s version %s", prognm, PACKAGE_VERSION);

	if (geteuid() != 0)
	{
		printf("Need root privileges to start.");
		usage();
	}
	
	while ((ch = getopt_long(argc, argv, "i:n:dv?", long_options, NULL)) != EOF) {

		switch (ch) {

		case 'i':
			strcpy(ip_address_parm, optarg);
			break;
			
		case 'n':
			strcpy(if_name_parm, optarg);
			break;
			
		case 'd':
			debug_enabled = true;
			break;
			
		case 'v':
			printf("%s\n", versionstring);
			return 0;
			
		case '?':
			usage();

		default:
			usage();
		}
	}

	if (strlen(if_name_parm) == 0)
	{
		printf("Interface option is required\n");
		list_interfaces();
		usage();
	}

	if (!is_valid_interface(if_name_parm))
	{
		printf("%s is not a valid interface\n", if_name_parm);
		list_interfaces();
		usage();
	}

	if (!debug_enabled && strlen(ip_address_parm) == 0)
	{
		printf("IP Address option is required\n");
		usage();
	}

	inet_pton(AF_INET, ip_address_parm, (void *) &ip_address);
	
	// fetch the network address and network mask
	pcap_lookupnet(if_name_parm, &pNet, &pMask, errbuf);

	descr = pcap_open_live(if_name_parm, BUFSIZ, 0, -1, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return -1;
	}

	if (pcap_compile(descr, &fp, NULL, 0, pNet) == -1)
	{
		printf("pcap_compile() failed\n");
		return -1;
	}

	if (pcap_setfilter(descr, &fp) == -1)
	{
		printf("pcap_setfilter() failed\n");
		exit(1);
	}

	pcap_loop(descr, 0, callback, NULL);

	printf("\nDone with packet sniffing!\n");
	return 0;
}