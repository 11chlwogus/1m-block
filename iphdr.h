#include <stdint.h>


struct iphdr{
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t sip;
    uint32_t dip;
};
