#pragma once
#include <stdint.h>
#include "ip.h"
#define UDP 17
#define TCP 6
#define Ipv4 0x0800
#pragma pack(push,1)
struct IpHdr{
    uint8_t ip_hl_:4,      /* header length */
        ip_v_:4;
    uint8_t ip_tos_;
    uint16_t ip_len_;         /* total length */
    uint16_t ip_id_;          /* identification */
    uint16_t ip_off_;
    uint8_t ip_ttl_;          /* time to live */
    uint8_t ip_p_;            /* protocol */
    uint16_t ip_sum_;         /* checksum */
    Ip sip_, dip_;
};

#pragma pack(pop)
