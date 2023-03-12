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

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation

    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)&iphdr;
    int len = iphdr.ihl * 4;  // Length of the IP header in bytes

    // Calculate the checksum
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *((uint8_t *)buf);
    }

    // Add the carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt and store it to struct Net
    // Return payload of network layer

    if (pkt_len < sizeof(struct iphdr)) {
        return NULL; // packet too short to be a valid IP packet
    }
    // extract IP header
    struct iphdr *ip_hdr = (struct iphdr *)pkt;
    self->ip4hdr = *ip_hdr;
    if (ip_hdr->protocol != IPPROTO_ESP) {
        self->pro = UNKN_PROTO;
        return NULL;
    }
    self->pro = ESP;
    // extract source and destination IP addresses
    char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->saddr, src_addr_str, sizeof(src_addr_str));
    inet_ntop(AF_INET, &ip_hdr->daddr, dst_addr_str, sizeof(dst_addr_str));
    self->src_ip = strdup(src_addr_str);
    self->dst_ip = strdup(dst_addr_str);

    // set expected source and destination IP addresses to NULL by default
    self->x_src_ip = NULL;
    self->x_dst_ip = NULL;

    // calculate the total length of the IP packet
    uint16_t tot_len = ntohs(ip_hdr->tot_len);
    if (pkt_len < tot_len) {
        return NULL; // packet truncated
    }

    // calculate the header length and payload length of the IP packet
    self->hdrlen = ip_hdr->ihl * 4;
    self->plen = tot_len - self->hdrlen;
    // return the payload of the IP packet (i.e., the data after the IP header)
    return pkt + self->hdrlen;

}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    // Set the IP header fields
    // self->ip4hdr.version = 4;                  // IPv4
    // self->ip4hdr.ihl = self->hdrlen / 4;        // Header length in 4-byte words
    // self->ip4hdr.tos = 0;                      // Type of service (unused)
    self->ip4hdr.tot_len = htons(self->plen);  // Total length of the IP packet (including header and data)
    // self->ip4hdr.id = htons(1);                // Identification field (unused)
    // self->ip4hdr.frag_off = 0;                 // Fragment offset (unused)
    // self->ip4hdr.ttl = 64;                     // Time-to-live
    // self->ip4hdr.protocol = self->pro;         // Protocol of the encapsulated packet
    self->ip4hdr.check = 0x00;
    // self->ip4hdr.protocol = IPPROTO_TCP;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);                    // Checksum (to be calculated later) cal_ipv4_cksm(struct iphdr iphdr)
    // self->ip4hdr.protocol = IPPROTO_ESP;
    // self->ip4hdr.saddr = inet_addr(self->src_ip);  // Source IP address (in network byte order)
    // self->ip4hdr.daddr = inet_addr(self->dst_ip);  // Destination IP address (in network byte order)

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
