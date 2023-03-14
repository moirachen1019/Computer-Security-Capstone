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

inline static struct sockaddr_ll init_addr(char *name) // Our Code
{
    struct sockaddr_ll addr; // device-independent physical-layer address
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    
    // get index from the interface name
    addr.sll_ifindex = if_nametoindex(name);
    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }
    
    //set other information
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_halen = ETH_ALEN;

    // get MAC address
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    struct ifreq ifr; // config of network interface
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1); // copy the interface name to ifr
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) { // request the hardware address
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

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp) // Our Code
{
    // [TODO]: store the whole frame into self->frame

    // calculate the total length of the packet
    int link_layer_Length = 14;
    size_t pktlen = link_layer_Length + sizeof(struct iphdr) + sizeof(EspHeader) + txp.hdrlen + txp.plen + esp.tlr.pad_len + sizeof(EspTrailer) + esp.authlen;
    self->framelen = pktlen;

    // allocate memory
    self->frame = (uint8_t *)malloc(pktlen);
    if (!self->frame) {
        fprintf(stderr, "Error: failed to allocate memory for frame\n");
        exit(EXIT_FAILURE);
    }
    
    int cur_length = 0; 
    // link layer header
    memcpy(self->frame + cur_length, self->linkhdr, link_layer_Length);
    cur_length += link_layer_Length;
    
    // IP header
    memcpy(self->frame + cur_length, &net.ip4hdr, sizeof(struct iphdr));
    cur_length += sizeof(struct iphdr);
    
    // ESP header
    memcpy(self->frame + cur_length, &esp.hdr, sizeof(EspHeader));
    cur_length += sizeof(EspHeader);
    
    // TCP header
    memcpy(self->frame + cur_length, &txp.thdr, txp.hdrlen);
    cur_length += txp.hdrlen;

    // TCP payload
    memcpy(self->frame + cur_length, txp.pl, txp.plen);
    cur_length += txp.plen;

    // add the padding data
    memcpy(self->frame + cur_length, esp.pad, esp.tlr.pad_len);
    cur_length += esp.tlr.pad_len;

    // ESP trailer
    memcpy(self->frame + cur_length, &esp.tlr, sizeof(EspTrailer));
    cur_length += sizeof(EspTrailer);

    // add the authentication data
    memcpy(self->frame + cur_length, esp.auth, esp.authlen);
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
