#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#define SC_CONST 0xdeadbeefdeadbeefLL
#define JHASH_GOLDEN_RATIO	0x9e3779b9

#define BLOOM_BITMAP_CAPACITY (1<<20)
#define BLOOM_BITMAP_LEN (BLOOM_BITMAP_CAPACITY>>3)
#define BLOOM_BITMAP_MASK (BLOOM_BITMAP_CAPACITY-1)

#define MAP_BIT_SET(map, bit) (map[bit>>3] |= (1 << (bit & 0x7)))
#define MAP_BIT_TEST(map, bit) (map[bit>>3] & (1 << (bit & 0x7)))

#define BLOOM_CFG_IP_ADDR_6TO4(ip6)  ((ip6[0] & 0xff000000) |(ip6[1] & 0xff000000 >> 8)|(ip6[2] & 0xff000000 >> 16)|(ip6[3] & 0xff000000 >> 24))
#define BLOOM_CFG_IP_ADDR_HASH0(sip, dip)  (((sip >> 8) & 0xfff000) | ((dip >> 20) & 0xfff))
#define BLOOM_CFG_IP_ADDR_HASH1(sip, dip) ((sip >> 8) & 0xffffff)
#define BLOOM_CFG_IP_ADDR_HASH2(sip, dip) ((dip >> 8) & 0xffffff)

//test related:
#define ALIVE printf("alive in %s:(line %d)\n", __FUNCTION__, __LINE__);
#define PRINT_HEX(u32) { \
    printf("%s(line %d): %s = 0x%x\n", __FUNCTION__, __LINE__, #u32, u32);\
}

#define PRINT_IPV4_ADDR(u32) { \
    uint8_t *u8 = (uint8_t*)&u32; \
    printf("%s line %d: ip addr %s: %x.%x.%x.%x\n", __FUNCTION__, __LINE__, #u32, u8[0], u8[1], u8[2], u8[3]);\
}

#define CONVERT_TO_IPV4_ADDR(repr, u32) {\
    u32 = 0; \
    const char *str = repr? repr:"0.0.0.0";\
    uint8_t *u8 = (uint8_t*)&u32; \
    const char *dot;\
    dot = strchr(str, '.');\
    *u8 = *u8 * 10 + (*str++ - '0');\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    str++;\
    dot = strchr(str, '.');\
    u8++;\
    *u8 = *u8 * 10 + (*str++ - '0');\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    str++;\
    dot = strchr(str, '.');\
    u8++;\
    *u8 = *u8 * 10 + (*str++ - '0');\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    str++;\
    dot = strchr(str, '\0');\
    u8++;\
    *u8 = *u8 * 10 + (*str++ - '0');\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    (str == dot) || (*u8 = *u8 * 10 + (*str++ - '0'));\
    str++;\
}
    

#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

typedef struct bloom_rule_cfg_st {
    /*
0: v4 sip+dip, 1: v4 sip, 2:v4 dip, 3: v4 mask 
4: v6 sip+dip, 5: v6 sip, 6:v6 dip, 7: v6 mask
    */
    uint8_t rule_type;
    uint32_t sip4;
    uint32_t dip4;
    uint32_t sip6[4];
    uint32_t dip6[4];
    uint32_t mask_sip4;
    uint32_t mask_dip4;
    uint32_t mask_sip6[4];
    uint32_t mask_dip6[4];
}bloom_rule_cfg_t;

typedef struct bloom_packet_cfg_st {
    uint8_t version_type/*4 or 6*/;
    uint32_t sip4;
    uint32_t dip4;
    uint32_t sip6[4];
    uint32_t dip6[4];
}bloom_packet_cfg_t;


//APIs
int bloom_init();
int bloom_add_rule(bloom_rule_cfg_t *cfg);
void bloom_clear_all();
int bloom_filter_packet_nomatch(bloom_packet_cfg_t *cfg);
void bloom_show_statistics();

//Utility functions
static inline uint64_t rot64(uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static inline void short_end
(
	uint64_t *h0,
	uint64_t *h1,
	uint64_t *h2,
	uint64_t *h3
)
{
	*h3 ^= *h2;  *h2 = rot64(*h2, 15);  *h3 += *h2;
	*h0 ^= *h3;  *h3 = rot64(*h3, 52);  *h0 += *h3;
	*h1 ^= *h0;  *h0 = rot64(*h0, 26);  *h1 += *h0;
	*h2 ^= *h1;  *h1 = rot64(*h1, 51);  *h2 += *h1;
	*h3 ^= *h2;  *h2 = rot64(*h2, 28);  *h3 += *h2;
	*h0 ^= *h3;  *h3 = rot64(*h3, 9);   *h0 += *h3;
	*h1 ^= *h0;  *h0 = rot64(*h0, 47);  *h1 += *h0;
	*h2 ^= *h1;  *h1 = rot64(*h1, 54);  *h2 += *h1;
	*h3 ^= *h2;  *h2 = rot64(*h2, 32);  *h3 += *h2;
	*h0 ^= *h3;  *h3 = rot64(*h3, 25);  *h0 += *h3;
	*h1 ^= *h0;  *h0 = rot64(*h0, 63);  *h1 += *h0;
}

static inline uint32_t __bloom_myspooky(uint32_t val)
{
    uint64_t h1 = (uint64_t)val, h2 = 0, h3 = SC_CONST,  h4 = SC_CONST;
    short_end(&h1, &h2, &h3, &h4);
    return (uint32_t)h1;
}

static inline uint32_t __bloom_myjhash(uint32_t val)
{
    uint32_t b = 0, c = JHASH_GOLDEN_RATIO;
    __jhash_mix(val, b, c);
    return val;
}


static inline void __bloom_insert(uint8_t *map, uint32_t val)
{
    uint32_t bit = __bloom_myspooky(val)&BLOOM_BITMAP_MASK;
    MAP_BIT_SET(map, bit);
    bit = __bloom_myjhash(val)&BLOOM_BITMAP_MASK;
    MAP_BIT_SET(map, bit);
}

/**
 * @brief test if bloom filter contains given value
 *
 * @param map
 * @param val
 *
 * @return 0 if map contains val, -1 otherwise 
 */
static inline int __bloom_contain(uint8_t *map, uint32_t val)
{
    uint32_t bit = __bloom_myspooky(val)&BLOOM_BITMAP_MASK;
    if (!MAP_BIT_TEST(map, bit)) return -1;
    bit = __bloom_myjhash(val)&BLOOM_BITMAP_MASK;
    if (!MAP_BIT_TEST(map, bit)) return -1;
    return 0;
}

static inline int __bloom_bitmask_count_one(uint32_t vec[], int len_vec)
{
    int sum = 0;
    int i;
    for (i = 0; i < len_vec; ++i) {
        uint32_t val = vec[i];
        while (val) {
            sum++;
            val &= (val-1);
        }
    }
    return sum;
}

static inline int __bloom_val_count_one(uint32_t val)
{
    int sum = 0;
    while (val) {
        sum++;
        val &= (val-1);
    }
    return sum;
}

#ifdef __cplusplus
}
#endif

#endif
