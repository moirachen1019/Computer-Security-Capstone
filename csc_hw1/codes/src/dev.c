#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"
#include "hmac.h"

inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr; // device-independent physical-layer address
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    
    // Get interface index from name
    addr.sll_ifindex = if_nametoindex(name);
    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    // Set family
    addr.sll_family = AF_PACKET;

    // Set protocol
    addr.sll_protocol = htons(ETH_P_ALL);

    // Set address length
    addr.sll_halen = ETH_ALEN;

    // Get MAC address of the interface
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl()");
        exit(EXIT_FAILURE);
    }
    memcpy(addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(sockfd);
    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen

    // // calculate the length of the ESP header and trailer
    // size_t esphdrlen = sizeof(EspHeader) + esp.plen + esp.tlr.pad_len;
    // size_t esptrailerlen = sizeof(EspTrailer) + esp.authlen;

    // // calculate the total length of the packet
    // size_t pktlen = net.hdrlen + esphdrlen + txp.hdrlen + txp.plen;
    // //size_t pktlen = 14 +  sizeof(struct iphdr);// ! 之後改不是常數

    // // allocate memory for the frame
    // self->frame = malloc(pktlen);
    // if (!self->frame) {
    //     fprintf(stderr, "Error: failed to allocate memory for frame\n");
    //     exit(EXIT_FAILURE);
    // }

    // // copy the link-layer header
    // memcpy(self->frame, self->linkhdr, 14); // ! 之後改不是常數
    
    // // copy the IP header
    // memcpy(self->frame + 14, &net.ip4hdr, sizeof(struct iphdr)); // ! 之後改不是常數

    // // copy the ESP header
    // // EspHeader *esphdr = (EspHeader *)(self->frame + net.hdrlen + sizeof(struct iphdr));
    // // esphdr->spi = htonl(esp.hdr.spi);
    // // esphdr->seq = htonl(esp.hdr.seq);
    // // uint8_t *padpl = esp.set_padpl(&esp);
    // // memcpy(self->frame + net.hdrlen + sizeof(struct iphdr) + sizeof(EspHeader), padpl, esp.plen + esp.tlr.pad_len);
    // memcpy(self->frame + 14 + sizeof(struct iphdr), &esp.hdr, sizeof(EspHeader)); 

    // memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader), &txp.thdr, txp.hdrlen);
    // memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen, txp.pl, txp.plen);

    // // memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader), &esp.pl, esp.plen); 

    // // // copy the ESP trailer
    // // EspTrailer *esptrailer = (EspTrailer *)(self->frame + net.hdrlen + sizeof(struct iphdr) + sizeof(EspHeader) + esp.plen + esp.tlr.pad_len);
    // // esptrailer->pad_len = esp.tlr.pad_len;
    // // esptrailer->nxt = net.pro;

    // // // copy the TCP header
    // // memcpy(self->frame + net.hdrlen + sizeof(struct iphdr) + esphdrlen, &txp.thdr, txp.hdrlen);

    // // // copy the TCP payload
    // // memcpy(self->frame + net.hdrlen + sizeof(struct iphdr) + esphdrlen + txp.hdrlen, txp.pl, txp.plen);

    // // set the length of the frame
    // self->framelen = pktlen;

    // calculate the length of the ESP header and trailer
    size_t esphdrlen = sizeof(EspHeader) + esp.plen + esp.tlr.pad_len;
    size_t esptrailerlen = sizeof(EspTrailer) + esp.authlen;

    // calculate the total length of the packet
    size_t pktlen = 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen + txp.plen + esp.tlr.pad_len + sizeof(EspTrailer) + esp.authlen;

    // allocate memory for the frame
    self->frame = (uint8_t *)malloc(pktlen);
    if (!self->frame) {
        fprintf(stderr, "Error: failed to allocate memory for frame\n");
        exit(EXIT_FAILURE);
    }

    // copy the link-layer header
    memcpy(self->frame, self->linkhdr, 14);

    // copy the IP header
    memcpy(self->frame + 14, &net.ip4hdr, sizeof(struct iphdr));

    // copy the ESP header
    memcpy(self->frame + 14 + sizeof(struct iphdr), &esp.hdr, sizeof(EspHeader));

    // copy the TCP header
    memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader), &txp.thdr, txp.hdrlen);
    printf("%02x\n", txp.thdr.th_sport);
    printf("%d\n", txp.hdrlen);

    // copy the TCP payload
    memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen, txp.pl, txp.plen);

    // add the padding data
    // uint8_t *padpl = esp.set_padpl(&esp);
    // uint8_t temp[esp.tlr.pad_len] = 0;
    memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen + txp.plen, esp.pad, esp.tlr.pad_len);
    // free(padpl);
    
    // copy the ESP trailer
    memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen + txp.plen + esp.tlr.pad_len, &esp.tlr, sizeof(EspTrailer));

    // // add the authentication data
    // uint8_t *auth = esp.set_auth(&esp, hmac_sha1);
    memcpy(self->frame + 14 + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen + txp.plen + esp.tlr.pad_len + sizeof(EspTrailer), esp.auth, esp.authlen);
    // free(auth);

    self->framelen = pktlen;
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
