#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <chrono>

#include "iphdr.h"
#include "tcphdr.h"

std::unordered_set<std::string> link_list;

void load_link_list(const char* filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        exit(1);
    }

    std::string line;
    auto start = std::chrono::high_resolution_clock::now();

    while (std::getline(file, line)) {
        size_t comma_pos = line.find(',');
        if (comma_pos != std::string::npos) {
            link_list.insert(line.substr(comma_pos + 1));
        } else {
            link_list.insert(line);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Total " << link_list.size() << " sites loaded into link_list." << std::endl;
    std::cout << "Loading time: " << elapsed.count() << " seconds\n" << std::endl;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet_data;
    int len;

    ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ntohl(ph->packet_id);

    len = nfq_get_payload(nfa, &packet_data);

    if(len >= 0) {
        struct iphdr *ip = (struct iphdr *)packet_data;

        // TCP 프로토콜(6)인지 확인
        if(ip->protocol == 6) {
            int ip_len = ip->ihl * 4;
            struct tcphdr *tcp = (struct tcphdr *)(packet_data + ip_len);

            // TCP 헤더 분석 (HTTP 포트 80인지 확인)
            if (ntohs(tcp->dest) == 80) {
                int tcp_len = tcp->doff * 4;
                unsigned char *payload = (unsigned char *)tcp + tcp_len;
                int payload_len = len - ip_len - tcp_len;

                // HTTP Payload 내 Host 필드 정밀 검사
                if (payload_len > 0) {
                    const char* payload_str = reinterpret_cast<const char*>(payload);
                    const char* host_ptr = strstr(payload_str, "Host: ");
                    
                    if (host_ptr) {
                        host_ptr += 6; // "Host: " 글자 수만큼 이동
                        const char* end_ptr = strstr(host_ptr, "\r\n");
                        
                        if (end_ptr) {
                            // 도메인 추출
                            std::string current_host(host_ptr, end_ptr - host_ptr);
                            
                            // 해시 테이블 검색 (O(1) 속도)
                            if (link_list.find(current_host) != link_list.end()) {
                                std::cout << "!!! Blocked: " << current_host << " !!!" << std::endl;
                                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                            }
                        }
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[]){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096];

    if(argc != 2){
        fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
        return 1;
    }

    load_link_list(argv[1]);

    h = nfq_open();
    if (!h){
        fprintf(stderr, "cant open handle\n");
        return 1;
    }

    if(nfq_bind_pf(h, AF_INET) < 0){
        fprintf(stderr, "error during nfq_bind_pf()\n");
        return 1;
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh){
        fprintf(stderr, "cant make queue\n");
        return 1;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
        fprintf(stderr, "cant set mode\n");
        return 1;
    }

    fd = nfq_fd(h); 
    while((rv = recv(fd, buf, sizeof(buf), 0))){
        if(rv >= 0){
            nfq_handle_packet(h, buf, rv);
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
