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
    uint16_t *buf;
    uint32_t sum = 0;
    int len = ntohs(iphdr.tot_len) - iphdr.ihl * 4;

    // allocate memory for pseudo-header + TCP header + payload
    buf = (uint16_t *)malloc(len + plen + sizeof(struct pseudo_hdr));
    if (!buf) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // construct pseudo-header
    struct pseudo_hdr phdr = {
        .src_addr = {iphdr.saddr},
        .dst_addr = {iphdr.daddr},
        .zeros = 0,
        .proto = IPPROTO_TCP,
        .len = htons(len)
    };

    // copy pseudo-header, TCP header, and payload into buffer
    memcpy(buf, &phdr, sizeof(struct pseudo_hdr));
    memcpy(buf + sizeof(struct pseudo_hdr) / 2, &tcphdr, sizeof(struct tcphdr));
    memcpy(buf + sizeof(struct pseudo_hdr) / 2 + sizeof(struct tcphdr) / 2, pl, plen);

    // compute checksum over buffer
    for (int i = 0; i < (len + plen + sizeof(struct pseudo_hdr)) / 2; i++) {
        sum += ntohs(buf[i]);
    }
    free(buf);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
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

