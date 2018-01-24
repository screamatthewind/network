#ifndef IGMP_H
#define IGMP_H

#include "defs.h"

#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define IGMP_MODE_IS_EXCLUDE 2
#define IGMP_CHANGE_TO_INCLUDE_MODE 3
#define IGMP_CHANGE_TO_EXCLUDE_MODE 4
#define IGMP_ALLOW_NEW_SOURCES 5
#define IGMP_BLOCK_OLD_SOURCES 6

struct igmpv3_grec {
	uint8_t  grec_type;
	uint8_t  grec_auxwords;
	uint16_t grec_nsrcs;
	uint32_t grec_mca;
	uint32_t grec_src[0];
};

struct igmpv3_report {
	uint8_t  type;
	uint8_t  resv1;
	uint16_t csum;
	uint16_t resv2;
	uint16_t ngrec;
	struct igmpv3_grec grec[0];
};

#endif