#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

struct pseudo_hdr {
    struct in_addr src_addr;
    struct in_addr dst_addr;
    uint8_t zeros;
    uint8_t proto;
    uint16_t len;
};

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    uint32_t sum = 0;
    uint16_t tcp_len = htons(sizeof(struct tcphdr) + plen);
    
    // Pseudo header (used in TCP checksum calculation)
    struct pseudo_tcp_hdr {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } p_tcp;
    
    memset(&p_tcp, 0, sizeof(struct pseudo_tcp_hdr));
    
    p_tcp.saddr = iphdr.saddr;
    p_tcp.daddr = iphdr.daddr;
    p_tcp.zero = 0;
    p_tcp.protocol = IPPROTO_TCP;
    p_tcp.length = tcp_len;
    
    // Calculate TCP checksum using the pseudo header and TCP header + payload
    uint16_t *buf = (uint16_t *) &p_tcp;
    int i;
    for (i = 0; i < sizeof(struct pseudo_tcp_hdr) / 2; i++) {
        sum += ntohs(buf[i]);
    }
    
    buf = (uint16_t *) &tcphdr;
    for (i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        sum += ntohs(buf[i]);
    }
    
    buf = (uint16_t *) pl;
    for (i = 0; i < plen / 2; i++) {
        sum += ntohs(buf[i]);
    }
    
    // Handle odd length payloads
    if (plen % 2) {
        sum += ((uint16_t) pl[plen - 1]) << 8;
    }
    
    // Add carry
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    // Take 1's complement
    sum = ~sum;
    
    return htons((uint16_t) sum);
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    // Check that the packet length is at least the size of the TCP header
    if (segm_len < sizeof(struct tcphdr)) {
        return NULL;
    }

    // Parse the TCP header
    if(segm!=NULL) self->thdr = *(struct tcphdr *)segm;
    //self->thdr.psh = 1;
    self->hdrlen = sizeof(struct tcphdr);

    // Verify that the segment length is at least as long as the TCP header
    if (segm_len < self->hdrlen) {
        return NULL;
    }

    // Parse the TCP payload
    self->plen = segm_len - self->hdrlen;
    // printf("%d\n", self->plen);
    self->pl = segm + self->hdrlen;
    
    // Update the expected TX sequence and acknowledgement numbers
    if (net->pro == TCP && self->x_src_port == ntohs(self->thdr.th_sport) && self->x_dst_port == ntohs(self->thdr.th_dport)) {
        self->x_tx_seq += self->plen;
        if (self->thdr.th_flags & TH_ACK) {
            self->x_tx_ack = ntohl(self->thdr.th_ack);
        }
    }

    return self->pl;

}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    // Set the TCP source and destination ports
    self->thdr.source = htons(self->x_src_port);
    self->thdr.dest = htons(self->x_dst_port);

    // Set the TCP sequence and acknowledge numbers
    self->thdr.seq = htonl(self->x_tx_seq);
    // printf("%d\n", self->x_tx_seq);
    self->thdr.ack_seq = htonl(self->x_tx_ack);

    // Set the TCP data offset (header length)
    self->hdrlen = sizeof(struct tcphdr);

    // Set the TCP flags
    // self->thdr.fin = 0;
    // self->thdr.syn = 0;
    // self->thdr.rst = 0;
    // self->thdr.psh = 1;
    // self->thdr.ack = 1;
    // self->thdr.urg = 0;

    // Set the TCP window size
    // self->thdr.window = htons(65535);

    // Set the TCP checksum to 0 for now (it will be calculated later)
    // cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
    // cal_tcp_cksm(iphdr, self->tcphdr, data, dlen)
    self->thdr.check = 0x00;
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, data, dlen);

    // Set the TCP urgent pointer to 0
    self->thdr.urg_ptr = 0;

    // Set the TCP payload and payload length
    self->pl = data;
    self->plen = dlen;

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

