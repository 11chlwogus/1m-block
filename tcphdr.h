#include <stdint.h>

struct tcphdr{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, flags:6;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
