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

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    struct sadb_msg msg;
    char buf[BUF_SIZE];
    int sock_fd;

    // Create PF_KEY socket
    if ((sock_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) < 0) {
        perror("socket");
        return;
    }

    // Prepare SADB_GET message to dump authentication key
    memset(&msg, 0, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_seq = time(NULL);

    if (write(sock_fd, &msg, sizeof(msg)) < 0) {
        perror("write");
        close(sock_fd);
        return;
    }

    // Receive SADB_GET response
    int n = read(sock_fd, buf, BUF_SIZE);
    if (n < 0) {
        perror("read");
        close(sock_fd);
        return;
    }

    struct sadb_ext *ext = (struct sadb_ext *)(buf + sizeof(struct sadb_msg));
    while ((char *)ext < (buf + n)) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key_ext = (struct sadb_key *) ext;
            uint8_t *auth_key = ((uint8_t *) key_ext) + sizeof(struct sadb_key);
            size_t auth_key_len = (key_ext->sadb_key_len * sizeof(uint64_t)) - sizeof(struct sadb_key);
            // for (int i = 0; i < auth_key_len; i++) {
            //     printf("%02x ", auth_key[i]);
            // }
            // printf("\n");
            memcpy(key, auth_key, auth_key_len);
            break;
        }
        ext = (struct sadb_ext *)((char *)ext + ((ext->sadb_ext_len * sizeof(uint64_t) + sizeof(uint64_t) - 1) / sizeof(uint64_t) * sizeof(uint64_t)));
    }
    close(sock_fd);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    // Determine how much padding is needed
    size_t total_len = sizeof(EspHeader) + self->plen + sizeof(EspTrailer) + self->authlen;
    size_t pad_len = ESP_BLOCK_SIZE - (total_len % ESP_BLOCK_SIZE);

    // Allocate memory for the padding
    uint8_t *pad = (uint8_t *)calloc(pad_len, sizeof(uint8_t));
    if (pad == NULL) {
        // Handle memory allocation error
        return NULL;
    }

    // Update Esp struct with the padding and its length
    self->pad = pad;
    self->tlr.pad_len = pad_len;

    return pad;

}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
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

    // Calculate the length of the payload and pad to 32-bit boundary
    size_t payload_len = self->plen;
    size_t padded_len = (payload_len % 4 == 0) ? payload_len : payload_len + (4 - payload_len % 4);
    nb += padded_len;

    // Add padding length field (4 bytes) to the buffer
    uint32_t pad_len_field = htonl(padded_len - payload_len);
    memcpy(buff, &pad_len_field, sizeof(uint32_t));
    nb += sizeof(uint32_t);

    // Copy the payload into the buffer
    memcpy(buff + nb, self->pl, payload_len);
    nb += payload_len;

    // *************************

    // Compute the HMAC
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // Parse the ESP header
    EspHeader *esp_hdr = (EspHeader *) esp_pkt;
    esp_pkt += sizeof(EspHeader);

    // Get the ESP payload length
    size_t plen = esp_len - sizeof(EspHeader) - sizeof(EspTrailer);

    // Get the ESP payload
    self->pl = esp_pkt;
    self->plen = plen;

    // Move to the ESP trailer
    esp_pkt += plen;

    // Parse the ESP trailer
    EspTrailer *esp_trl = (EspTrailer *) esp_pkt;
    esp_pkt += sizeof(EspTrailer);

    // Set the ESP padding
    size_t padlen = esp_trl->pad_len;
    self->pad = esp_pkt;
    esp_pkt += padlen;

    // Set the ESP trailer
    self->tlr = *esp_trl;

    // Set the ESP authentication data
    size_t authlen = esp_len - sizeof(EspHeader) - plen - padlen - sizeof(EspTrailer);
    self->auth = esp_pkt;
    self->authlen = authlen;

    esp_pkt = esp_pkt - padlen - plen - sizeof(EspHeader);
    // Return the ESP payload
    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
    
    // Set the protocol type to ESP
    p = ESP;

    // Set the next protocol in the trailer to the value of 'p'
    self->tlr.nxt = (uint8_t)p;

    // Calculate the padding length needed to make the packet a multiple of 4 bytes
    size_t pad_len = 4 - ((sizeof(EspHeader) + self->plen + sizeof(EspTrailer)) % 4);
    if (pad_len == 4) {
        pad_len = 0;
    }

    // Set the padding length in the trailer
    self->tlr.pad_len = pad_len;

    // Allocate memory for the padded payload and copy the payload data into it
    size_t padded_len = sizeof(EspHeader) + self->plen + pad_len + sizeof(EspTrailer);
    uint8_t *padded_payload = malloc(padded_len);
    if (padded_payload == NULL) {
        return NULL;  // Failed to allocate memory for padded payload
    }
    memcpy(padded_payload + sizeof(EspHeader), self->pl, self->plen);

    // Add padding bytes (if needed)
    if (pad_len > 0) {
        memset(padded_payload + sizeof(EspHeader) + self->plen, 0, pad_len);
    }

    // Copy the ESP header and trailer into the padded payload buffer
    memcpy(padded_payload, &self->hdr, sizeof(EspHeader));
    memcpy(padded_payload + sizeof(EspHeader) + self->plen + pad_len, &self->tlr, sizeof(EspTrailer));

    // Set the payload pointer and length to the padded payload
    self->pl = padded_payload + sizeof(EspHeader);
    self->plen = self->plen + pad_len;

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
