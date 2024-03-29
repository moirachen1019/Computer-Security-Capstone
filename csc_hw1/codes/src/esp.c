#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>
#include <linux/netlink.h>
#include <time.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

#define IPPROTO_ANY 25
#define ESP_BLOCK_SIZE 4
#define BUF_SIZE 2048

EspHeader esp_hdr_rec;

typedef struct {
    int type;
    uint8_t *key;
} SecurityAssociation;

SecurityAssociation *sadb;  // global SADB
#define num_security_associations 2
#define KEY_LENGTH 16   

void get_ik(int type, uint8_t *key) // Our code
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    struct sadb_msg msg;
    char buf[BUF_SIZE];
    int sock_fd;

    // create PF_KEY socket
    if ((sock_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) < 0) {
        perror("socket");
        return;
    }

    // set SADB_DUMP
    memset(&msg, 0, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_seq = time(NULL);

    // request SADB_DUMP
    if (write(sock_fd, &msg, sizeof(msg)) < 0) {
        perror("write");
        close(sock_fd);
        return;
    }

    // receive SADB_DUMP
    int n = read(sock_fd, buf, BUF_SIZE);
    if (n < 0) {
        perror("read");
        close(sock_fd);
        return;
    }

    // extract key extension
    struct sadb_ext *ext = (struct sadb_ext *)(buf + sizeof(struct sadb_msg));
    while ((char *)ext < (buf + n)) {
        // find the SADB_EXT_KEY_AUTH type
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key_ext = (struct sadb_key *) ext;
            // extract key
            uint8_t *auth_key = ((uint8_t *) key_ext) + sizeof(struct sadb_key);
            size_t auth_key_len = (key_ext->sadb_key_len * sizeof(uint64_t)) - sizeof(struct sadb_key);
            memcpy(key, auth_key, auth_key_len);
            break;
        }
        // go to the next key extension
        ext = (struct sadb_ext *)((char *)ext + ((ext->sadb_ext_len * sizeof(uint64_t) + sizeof(uint64_t) - 1) / sizeof(uint64_t) * sizeof(uint64_t)));
    }
    close(sock_fd);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self) // Our code
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    // calculate total length & padding length
    size_t total_len = sizeof(EspHeader) + self->plen + sizeof(EspTrailer);
    size_t pad_len = ESP_BLOCK_SIZE - (total_len % ESP_BLOCK_SIZE);

    // allocate memory and fill padding
    uint8_t *pad = (uint8_t *)malloc(pad_len * sizeof(uint8_t));
    if (pad == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < pad_len; i++) {
        if(i % 4 == 0) pad[i] = 0x01;
        else if(i % 4 == 1) pad[i] = 0x02;
        else if(i % 4 == 2) pad[i] = 0x03;
    }

    self->pad = pad;
    self->tlr.pad_len = pad_len;

    return pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *)) // Our code
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    // copy ESP header to buffer
    memcpy(buff + nb, &(self->hdr), sizeof(EspHeader));
    nb += sizeof(EspHeader);

    // ESP payload
    memcpy(buff + nb, self->pl, self->plen);
    nb += self->plen;

    // padding & payload
    memcpy(buff + nb, self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;

    // ESP trailer
    memcpy(buff + nb, &(self->tlr), sizeof(EspTrailer));
    nb += sizeof(EspTrailer);

    // compute HMAC & set authlen
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);
    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }
    self->authlen = ret;

    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len) // Our code
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // extract ESP header
    EspHeader *esp_hdr = (EspHeader *) esp_pkt;

    // set ESP header (spi & seq)
    self->hdr.spi = esp_hdr->spi;
    uint32_t value = htonl(esp_hdr->seq);
    value += 1;
    self->hdr.seq = ntohl(value);

    // set ESP payload length
    size_t plen = esp_len - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN;

    // move to ESP payload and set it
    esp_pkt += sizeof(EspHeader);
    self->pl = esp_pkt;
    
    // move to ESP trailer and extract it
    esp_pkt += plen;
    EspTrailer *esp_trl = (EspTrailer *) esp_pkt;

    // move to ESP padding and set it
    esp_pkt += sizeof(EspTrailer);
    size_t padlen = esp_trl->pad_len;
    plen -= padlen;
    self->plen = plen;
    self->pad = esp_pkt;

    // set ESP trailer
    self->tlr = *esp_trl;

    // set ESP authentication data
    size_t authlen = esp_len - sizeof(EspHeader) - plen - padlen - sizeof(EspTrailer);
    self->auth = esp_pkt;
    self->authlen = authlen;

    esp_pkt = esp_pkt - padlen - plen - sizeof(EspHeader);

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p) // Our code
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)

    // calculate padding length (the packet length has to be a multiple of 4)
    size_t pad_len = 4 - ((sizeof(EspHeader) + self->plen + sizeof(EspTrailer)) % 4);
    if (pad_len == 4) {
        pad_len = 0;
    }    

    // allocate memory for the padded payload
    size_t padded_len = sizeof(EspHeader) + self->plen + pad_len + sizeof(EspTrailer);
    uint8_t *padded_payload = malloc(padded_len);
    if (padded_payload == NULL) {
        return NULL;
    }
    memcpy(padded_payload + sizeof(EspHeader), self->pl, self->plen);

    // add padding
    if (pad_len > 0) {
        memset(padded_payload + sizeof(EspHeader) + self->plen, 0, pad_len);
    }

    // set ESP header (spi & seq)
    self->hdr.seq = htonl(esp_hdr_rec.seq);
    self->hdr.spi = esp_hdr_rec.spi;
    memcpy(padded_payload, &self->hdr, sizeof(EspHeader));

   // set ESP trailer
    self->tlr.pad_len = pad_len;
    self->tlr.nxt = (uint8_t)p; // the next protocol
    memcpy(padded_payload + sizeof(EspHeader) + self->plen + pad_len, &self->tlr, sizeof(EspTrailer));

    // payload points to the padded payload
    self->pl = padded_payload + sizeof(EspHeader);

    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
} 