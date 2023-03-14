#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr) // Our code
{
    // [TODO]: Finish IP checksum calculation

    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)&iphdr;
    int len = iphdr.ihl * 4;  // length of the IP header (bytes)

    // calculate checksum
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *((uint8_t *)buf);
    }

    // add the carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len) // Our code
{
    // [TODO]: Collect information from pkt and store it to struct Net
    // Return payload of network layer

    if (pkt_len < sizeof(struct iphdr)) {
        return NULL;
    }

    // extract IP header from packet
    struct iphdr *ip_hdr = (struct iphdr *)pkt;
    self->ip4hdr = *ip_hdr;
    if (ip_hdr->protocol != IPPROTO_ESP) {
        self->pro = UNKN_PROTO;
        return NULL;
    }
    self->pro = ESP;

    // set source & destination IP addresses
    char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->saddr, src_addr_str, sizeof(src_addr_str));
    inet_ntop(AF_INET, &ip_hdr->daddr, dst_addr_str, sizeof(dst_addr_str));
    self->src_ip = strdup(src_addr_str);
    self->dst_ip = strdup(dst_addr_str);

    // set expected source & destination IP addresses
    self->x_src_ip = self->dst_ip;
    self->x_dst_ip = self->src_ip;

    // calculate the total length of the IP packet
    uint16_t tot_len = ntohs(ip_hdr->tot_len);
    if (pkt_len < tot_len) {
        return NULL;
    }

    // calculate the header length & payload length of the IP packet
    self->hdrlen = ip_hdr->ihl * 4;
    self->plen = tot_len - self->hdrlen;
    
    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self) // Our code
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    // set total length (header length + data length)
    self->ip4hdr.tot_len = htons(self->hdrlen) + htons(self->plen);

    // set checksum
    self->ip4hdr.check = 0x00;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);

    self->ip4hdr.saddr = inet_addr(self->x_src_ip);
    self->ip4hdr.daddr = inet_addr(self->x_dst_ip);

    return self;
}

void init_net(Net *self)
{
    if (!self) {

        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
