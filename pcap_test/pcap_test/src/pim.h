#ifndef PIM_H
#define PIM_H

#include "defs.h"

#define GET_BYTE(val, cp)       ((val) = *(cp)++)

#define GET_NETLONG(val, cp)                    \
        do {                                    \
                uint32_t Xv;                    \
                Xv  = *(cp)++;                  \
                Xv |= (*(cp)++) <<  8;          \
                Xv |= (*(cp)++) << 16;          \
                Xv |= (*(cp)++) << 24;          \
                (val) = Xv;                     \
        } while (0)

#define GET_EUADDR(eua, cp)                     \
        do {                                    \
            (eua)->addr_family = *(cp)++;       \
            (eua)->encod_type  = *(cp)++;       \
            GET_NETLONG((eua)->unicast_addr, (cp)); \
        } while(0)

#define GET_HOSTSHORT(val, cp)                  \
        do {                                    \
                uint16_t Xv;                    \
                Xv = (*(cp)++) << 8;            \
                Xv |= *(cp)++;                  \
                (val) = Xv;                     \
        } while (0)

#define GET_EGADDR(ega, cp)                     \
        do {                                    \
            (ega)->addr_family = *(cp)++;       \
            (ega)->encod_type  = *(cp)++;       \
            (ega)->reserved    = *(cp)++;       \
            (ega)->masklen     = *(cp)++;       \
            GET_NETLONG((ega)->mcast_addr, (cp)); \
        } while(0)
	        
#define GET_ESADDR(esa, cp)                     \
        do {                                    \
            (esa)->addr_family = *(cp)++;       \
            (esa)->encod_type  = *(cp)++;       \
            (esa)->flags       = *(cp)++;       \
            (esa)->masklen     = *(cp)++;       \
            GET_NETLONG((esa)->src_addr, (cp)); \
        } while(0)
	        
/* Encoded-Group */
typedef struct pim_encod_grp_addr_ {
    uint8_t      addr_family;
    uint8_t      encod_type;
    uint8_t      reserved;
    uint8_t      masklen;
    uint32_t     mcast_addr;
} pim_encod_grp_addr_t;
#define PIM_ENCODE_GRP_ADDR_LEN 8

/* Encoded-Source */
typedef struct pim_encod_src_addr_ {
    uint8_t      addr_family;
    uint8_t      encod_type;
    uint8_t      flags;
    uint8_t      masklen;
    uint32_t     src_addr;
} pim_encod_src_addr_t;
#define PIM_ENCODE_SRC_ADDR_LEN 8

typedef struct pim_t {
#ifdef _PIM_VT
	uint8_t         pim_vt; /* PIM version and message type */
#else /* ! _PIM_VT   */
#if BYTE_ORDER == BIG_ENDIAN
	u_int           pim_vers : 4, /* PIM protocol version         */
	                pim_type : 4; /* PIM message type             */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int           pim_type : 4, /* PIM message type             */
	                pim_vers : 4; /* PIM protocol version         */
#endif
#endif /* ! _PIM_VT  */
	uint8_t         pim_reserved; /* Reserved                     */
	uint16_t        pim_cksum; /* IP-style checksum            */
} pim_t;


/* Encoded-Unicast: 6 bytes long */
typedef struct pim_encod_uni_addr_ {
    uint8_t      addr_family;
    uint8_t      encod_type;
    uint32_t     unicast_addr;        /* XXX: Note the 32-bit boundary
				      * misalignment for  the unicast
				      * address when placed in the
				      * memory. Must read it byte-by-byte!
				      */
} pim_encod_uni_addr_t;

#endif