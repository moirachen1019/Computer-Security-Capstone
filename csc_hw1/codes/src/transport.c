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

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen) // Our code
{
    // [TODO]: Finish TCP checksum calculation
    uint32_t sum = 0;
    uint16_t tcp_len = htons(sizeof(struct tcphdr) + plen);
    
    // set pseudo header for checksum
    struct pseudo_hdr p_tcp;
    memset(&p_tcp, 0, sizeof(struct pseudo_hdr));
    p_tcp.src_addr = iphdr.saddr;
    p_tcp.dst_addr = iphdr.daddr;
    p_tcp.zeros = 0;
    p_tcp.proto = IPPROTO_TCP;
    p_tcp.len = tcp_len;
    
    // calculate checksum using pseudo header + TCP header + payload
    uint16_t *buf = (uint16_t *) &p_tcp;
    for (int i = 0; i < sizeof(struct pseudo_hdr) / 2; i++) {
        sum += ntohs(buf[i]);
    }
    buf = (uint16_t *) &tcphdr;
    for (int i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        sum += ntohs(buf[i]);
    }
    buf = (uint16_t *) pl;
    for (int i = 0; i < plen / 2; i++) {
        sum += ntohs(buf[i]);
    }
    // handle odd length payloads
    if (plen % 2) {
        sum += ((uint16_t) pl[plen - 1]) << 8;
    }
    // add carry
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    } 
    // take 1's complement
    sum = ~sum;
    return htons((uint16_t) sum);
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len) // Our code
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    if (segm_len < sizeof(struct tcphdr)) {
        return NULL;
    }

    // parse TCP header
    if(segm != NULL) {
        self->thdr = *(struct tcphdr *)segm;
    }
    self->hdrlen = sizeof(struct tcphdr);

    // parse TCP payload
    self->plen = segm_len - self->hdrlen;
    self->pl = segm + self->hdrlen;
    self->x_tx_seq = (self->thdr.th_ack);
    self->x_tx_acntohlk = ntohl(self->thdr.th_seq) + self->plen;
    self->x_src_port = ntohs(self->thdr.th_dport);
    self->x_dst_port = ntohs(self->thdr.th_sport);

    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen) // Our code
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    // set source ports & destination ports & sequence & acknowledge
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);

    // set data offset (header length)
    self->hdrlen = sizeof(struct tcphdr);

    // set psh flag
    if(dlen==0) {
        self->thdr.psh = 0;
    }

    // set checksum
    self->thdr.check = 0x00;
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, data, dlen);

    // set payload & payload length
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

