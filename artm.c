/*
 *  SEPART stuff
 *
 *  Copyright (c) 2017 xerub
 */

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#endif
#include <libDER/DER_Decode.h>
#include <libDER/asn1Types.h>

#define DEBUG 1

static const unsigned char key[] = {
  0xa4, 0xca, 0x55, 0x3b, 0x56, 0x56, 0x25, 0x9c, 0x82, 0x56, 0xb0, 0x54, 0x32, 0xe7, 0x1e, 0x76,
  0x2e, 0xf7, 0x7f, 0xaf, 0xc9, 0x2c, 0xf0, 0x48, 0xf1, 0x64, 0x3c, 0x48, 0xcd, 0xbe, 0x0e, 0x3b
};
static const unsigned int key_len = 32;

static const DERItemSpec ARTItemSpecs[] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,         0 },
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE, DER_DEC_SAVE_DER/*|DER_ENC_WRITE_DER*/ },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,    0 },
};

static void __attribute__((format(printf, 3, 4)))
print_bytes(const unsigned char *octet, size_t len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    while (len--) {
        printf("%02x", *octet++);
    }
    printf("\n");
}

#ifdef DEBUG
static const DERItemSpec SubARTItemSpecs[] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,         0 }, // counter
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING,    0 }, // manifest hash
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,    0 }, // sleep hash
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,    0 }, // restore nonce (snon)
    { 4 * sizeof(DERItem), ASN1_CONSTR_SET,      0 }, // subcounters
};

static int
print_art(const DERItem *item)
{
    int rv;
    uint64_t counter;
    DERItem items[5];
    DERSequence seq;

    rv = DERParseSequence(item, 5, SubARTItemSpecs, items, sizeof(items));
    if (rv) {
        fprintf(stderr, "error: cannot parse SEQUENCE\n");
        return rv;
    }

    rv = DERParseInteger64(&items[0], &counter);
    if (rv) {
        fprintf(stderr, "error: cannot get counter\n");
        return rv;
    }

    printf("cntr: 0x%llx\n", counter);

    if (items[1].length) {
        print_bytes(items[1].data, items[1].length, "mani: ");
    }

    if (items[2].length) {
        print_bytes(items[2].data, items[2].length, "slep: ");
    }

    if (items[3].length) {
        print_bytes(items[3].data, items[3].length, "snon: ");
    }

    rv = DERDecodeSeqContentInit(&items[4], &seq);
    while (rv == 0) {
        DERDecodedInfo info;
        rv = DERDecodeSeqNext(&seq, &info);
        if (rv == DR_EndOfSequence) {
            return 0;
        }
        if (rv == 0) {
            print_bytes(info.content.data, info.content.length, "elem: tag=0x%llx, size=%u: ", (uint64_t)info.tag, info.content.length);
        }
    }
    if (rv) {
        fprintf(stderr, "error: internal SET (%d)\n", rv);
    }
    return rv;
}
#endif	/* DEBUG */

static unsigned char *
read_file(const char *filename, size_t *size)
{
    int fd;
    size_t rv, sz;
    struct stat st;
    unsigned char *buf;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    rv = fstat(fd, &st);
    if (rv) {
        close(fd);
        return NULL;
    }

    sz = st.st_size;

    buf = malloc(sz);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }

    rv = read(fd, buf, sz);
    close(fd);

    if (rv != sz) {
        free(buf);
        return NULL;
    }

    if (size != NULL) {
        *size = sz;
    }
    return buf;
}

int
main(int argc, char **argv)
{
    size_t sz;
    DERItem item;
    DERItem items[3];
    uint64_t version;
    unsigned char md[32];
    const char *artfile = (argc > 1) ? argv[1] : "ART.bin";
    int rv = -1;

    assert(key_len == 32);

    item.data = read_file(artfile, &sz);
    if (!item.data) {
        fprintf(stderr, "error: cannot read %s\n", artfile);
        goto done;
    }
    item.length = sz;

    rv = DERParseSequence(&item, 3, ARTItemSpecs, items, sizeof(items));
    if (rv) {
        fprintf(stderr, "error: cannot parse %s\n", artfile);
        goto done;
    }

    rv = DERParseInteger64(&items[0], &version);
    if (rv) {
        fprintf(stderr, "error: cannot get ART version (%d)\n", rv);
        goto done;
    }
    rv = -1;
    if (version) {
        fprintf(stderr, "error: bad ART version: %llu\n", version);
        goto done;
    }
    if (items[2].length != 32) {
        fprintf(stderr, "error: bad HMAC length: %u\n", items[2].length);
        goto done;
    }

#ifdef DEBUG
    print_art(&items[1]);
    print_bytes(items[2].data, items[2].length, "hmac: ");
#endif

#ifdef USE_CORECRYPTO
    cchmac(ccsha256_di(), key_len, key, items[1].length, items[1].data, md);
#else
    unsigned int md_len;
    unsigned char *p = HMAC(EVP_sha256(), key, key_len, items[1].data, items[1].length, md, &md_len);
    assert(p && md_len == 32);
#endif

    if (!memcmp(items[2].data, md, 32)) {
        printf("OK\n");
        rv = 0;
    } else {
#ifndef DEBUG
        print_bytes(items[2].data, items[2].length, "hmac: ");
#endif
        print_bytes(md, 32, "real: ");
        printf("FAIL\n");
    }

done:
    free(item.data);
    return rv;
}
