#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr{
    unsigned int ihl:4;
    unsigned int version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    Ip sip_;
    Ip dip_;
    

    uint32_t hl()
    {
        return ihl;
    }
    uint32_t sip()
    {
        return ntohl(sip_);
    }
    uint32_t dip()
    {
        return ntohl(dip_);
    }
    uint16_t tlen()
    {
        return ntohs(tot_len);
    }
};
#pragma pack(pop)