struct dev { // network interface
    int mtu;

    struct sockaddr_ll addr;
    int fd;

    uint8_t *frame;
    uint16_t framelen;

    uint8_t *linkhdr;

    void (*fmt_frame)(Dev *self, Net net, Esp esp, Txp txp);
    ssize_t (*tx_frame)(Dev *self);
    ssize_t (*rx_frame)(Dev *self);
};

typedef struct esp_header {
    uint32_t spi;
    uint32_t seq;
} EspHeader;

typedef struct esp_trailer {
    uint8_t pad_len;
    uint8_t nxt;
} EspTrailer;

struct esp { // Encapsulating Security Payload protocol
    EspHeader hdr;

    uint8_t *pl;    // ESP payload
    size_t plen;    // ESP payload length

    uint8_t *pad;   // ESP padding

    EspTrailer tlr;

    uint8_t *auth;
    size_t authlen;

    uint8_t *esp_key;

    uint8_t *(*set_padpl)(Esp *self);
    uint8_t *(*set_auth)(Esp *self,
                         ssize_t (*hmac)(uint8_t const *, size_t,
                                         uint8_t const *, size_t,
                                         uint8_t *));
    void (*get_key)(Esp *self);
    uint8_t *(*dissect)(Esp *self, uint8_t *esp_pkt, size_t esp_len);
    Esp *(*fmt_rep)(Esp *self, Proto p);
};

typedef enum proto {
    UNKN_PROTO = 0,

    IPv4 = IPPROTO_IP,

    ESP = IPPROTO_ESP,

    TCP = IPPROTO_TCP,
} Proto;

struct net { // IP network layer protocol
    char *src_ip;
    char *dst_ip;

    char *x_src_ip; /* Expected src IP addr */
    char *x_dst_ip; /* Expected dst IP addr */

    struct iphdr ip4hdr;

    size_t hdrlen;
    uint16_t plen;
    Proto pro;

    uint8_t *(*dissect)(Net *self, uint8_t *pkt, size_t pkt_len);
    Net *(*fmt_rep)(Net *self);
};

struct txp { // transport layer
    uint16_t x_src_port; /* Expected src port to CSCF */
    uint16_t x_dst_port; /* Expected dst port to CSCF */

    uint32_t x_tx_seq; /* Expected tx sequence number */
    uint32_t x_tx_ack; /* Expected tx acknowledge number */

    struct tcphdr thdr;
    uint8_t hdrlen;

    uint8_t *pl;
    uint16_t plen;

    uint8_t *(*dissect)(Net *net, Txp *self, uint8_t *txp_data, size_t txp_len);
    Txp *(*fmt_rep)(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen);
};