#include <iostream>
#include <arpa/inet.h>
#include "boost/asio.hpp"
#include "bloom_filter.h"

using namespace std;
using namespace boost;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::ip::address;


string represent_v6_addr(uint32_t v6_array[]) 
{
    address_v6::bytes_type bytes;
    for (int i = 0; i < 4; ++i) {
        int j = i << 2;
        bytes[j] = (v6_array[i]&0xff000000) >> 24;
        bytes[j+1] = (v6_array[i]&0xff0000) >> 16;
        bytes[j+2] = (v6_array[i]&0xff00) >> 8;
        bytes[j+3] = (v6_array[i]&0xff);
    }
    return address_v6(bytes).to_string();
}

int debug_match_packet(bloom_packet_cfg_t *ppcfg)
{
    int res = bloom_filter_packet_nomatch(ppcfg);

    if (res != 1) {
        cout << "hit rule."; 
    } else {
        cout << "miss rule.";
    }

    if (ppcfg->version_type == 4) {
        cout << "sip: " << (address_v4(ppcfg->sip4)) 
            << ", dip: " << (address_v4(ppcfg->dip4)) 
            << endl;
    } else {
        cout 
            << "sip: " << represent_v6_addr(ppcfg->sip6) << "(" <<  address_v4(ppcfg->sip4) << ")" << ", dip: " << represent_v6_addr(ppcfg->dip6) << "(" <<  address_v4(ppcfg->sip4) << ")" 
            << endl;
    }
    
    return res;
}

void fill_v6_addr(const char *str, uint32_t v6_array[])
{
    if (strcmp(str, "random") == 0) {
        for (int i = 0; i < 4; ++i) {
            v6_array[i] = (uint32_t)rand();
        }
    } else {
        address_v6::bytes_type bytes = address_v6::from_string(str).to_bytes();
        for (int i = 0; i < 4; ++i) {
            int j = i << 2;
            v6_array[i] = (bytes[j] << 24)|(bytes[j+1] << 16)|(bytes[j+2] << 8)|(bytes[j+3]);
        }
    }
}

void train_v4_mask()
{
    bloom_rule_cfg_t rcfg;
    rcfg.rule_type = 3;

    rcfg.sip4 = (10<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.dip4 = (100<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0xffffff00;
    rcfg.mask_sip4 = 0;
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (20<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (110<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (120<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (120<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (40<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (40<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (50<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (130<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (50<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (130<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (140<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (140<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (70<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (70<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.dip4 = (150<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (150<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }


    rcfg.sip4 = (90<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (90<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (100<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (160<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (100<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (160<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }
    
    rcfg.sip4 = (110<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (170<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (110<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (170<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }
    
    rcfg.sip4 = (120<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.sip4 = (120<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_dip4 = 0;
    rcfg.mask_sip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    rcfg.dip4 = (180<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.dip4 = (180<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4 += 0x100;
    }

    rcfg.sip4 = (140<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (190<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 325*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }
    
    rcfg.sip4 = (140<<24)|(50<<16)|(0<<8)|(1);
    rcfg.dip4 = (190<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = 0xffffff00;
    rcfg.mask_dip4 = 0xffffff00;
    for (int i = 0; i < 325*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
        rcfg.dip4 += 0x100;
    }

}

void train_v4_nomask()
{
    bloom_rule_cfg_t rcfg;

    rcfg.rule_type = 2;
    rcfg.dip4 = (100<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 12500*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4++;
    }

    rcfg.rule_type = 0;
    rcfg.sip4 = (20<<24)|(0<<16)|(0<<8)|(1);
    rcfg.dip4 = (110<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 12500*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip4++;
        rcfg.sip4++;
    }

    rcfg.rule_type = 2;
    rcfg.dip4 = (120<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 6250*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.dip4++;
    }

    rcfg.rule_type = 2;
    rcfg.dip4 = (130<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 6250*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.dip4++;
    }

    rcfg.rule_type = 0;
    rcfg.sip4 = (60<<24)|(0<<16)|(0<<8)|(1);
    rcfg.dip4 = (150<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 3125*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.dip4++;
        rcfg.sip4++;
    }

    rcfg.rule_type = 1;
    rcfg.sip4 = (50<<24)|(0<<16)|(0<<8)|(1);
    for (int i = 0; i < 3125*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.sip4++;
    }
}

void filter_v4(uint32_t packets_count)
{
    bloom_packet_cfg_t pcfg;
    pcfg.version_type = 4;
    for (uint32_t i = 0; i < packets_count; ++i) {
        pcfg.sip4 = (uint32_t)rand(); 
        pcfg.dip4 = (uint32_t)rand();
        bloom_filter_packet_nomatch(&pcfg);
    }
    bloom_show_statistics();
}

void filter_v6(uint32_t packets_count)
{
    bloom_packet_cfg_t pcfg;
    pcfg.version_type = 6;
    for (uint32_t i = 0; i < packets_count; ++i) {
        fill_v6_addr("random", pcfg.sip6); 
        fill_v6_addr("random", pcfg.dip6); 
        bloom_filter_packet_nomatch(&pcfg);
    }
    bloom_show_statistics();
}

void train_v6_mask()
{
    bloom_rule_cfg_t rcfg;
    rcfg.rule_type = 7;

    fill_v6_addr("2001::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("0::0", rcfg.mask_dip6);
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }

    fill_v6_addr("3001::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2002::1:1", rcfg.dip6);
    fill_v6_addr("3002::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 400*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("3003::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("3004::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2003::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }

    fill_v6_addr("2004::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }

    fill_v6_addr("2005::1:1", rcfg.dip6);
    fill_v6_addr("3005::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2006::1:1", rcfg.dip6);
    fill_v6_addr("3006::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }

//////
//
//
    
    fill_v6_addr("3007::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }
    fill_v6_addr("3008::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2007::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }
    fill_v6_addr("2008::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }


    fill_v6_addr("3009::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }
    fill_v6_addr("3010::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }


    fill_v6_addr("2009::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }
    fill_v6_addr("2010::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }

    fill_v6_addr("2011::1:1", rcfg.dip6);
    fill_v6_addr("3011::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }


    fill_v6_addr("2012::1:1", rcfg.dip6);
    fill_v6_addr("3012::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }
    fill_v6_addr("2013::1:1", rcfg.dip6);
    fill_v6_addr("3013::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }
    fill_v6_addr("2014::1:1", rcfg.dip6);
    fill_v6_addr("3014::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }


    fill_v6_addr("2015::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }
    fill_v6_addr("2016::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("::", rcfg.mask_dip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
    }


    fill_v6_addr("3015::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }
    fill_v6_addr("3016::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6); 
    fill_v6_addr("::", rcfg.mask_sip6);
    for (int i = 0; i < 200*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2017::1:1", rcfg.dip6);
    fill_v6_addr("3017::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 325*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }

    fill_v6_addr("2018::1:1", rcfg.dip6);
    fill_v6_addr("3018::1:1", rcfg.dip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_dip6);
    for (int i = 0; i < 325*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x10000;
        rcfg.dip6[3] += 0x10000;
    }
}

void train_v6_nomask()
{
    bloom_rule_cfg_t rcfg;

    rcfg.rule_type = 6;
    fill_v6_addr("100::1", rcfg.dip6); 
    for (int i = 0; i < 12500*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x1;
    }

    rcfg.rule_type = 4;
    fill_v6_addr("210::1", rcfg.sip6); 
    fill_v6_addr("110::1", rcfg.dip6); 
    for (int i = 0; i < 12500*16; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x1;
        rcfg.dip6[3] += 0x1;
    }

    rcfg.rule_type = 6;
    fill_v6_addr("120::1", rcfg.dip6); 
    for (int i = 0; i < 6250*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x1;
    }

    rcfg.rule_type = 6;
    fill_v6_addr("130::1", rcfg.dip6); 
    for (int i = 0; i < 6250*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x1;
    }

    rcfg.rule_type = 4;
    fill_v6_addr("240::1", rcfg.sip6); 
    fill_v6_addr("150::1", rcfg.dip6); 
    for (int i = 0; i < 3125*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x1;
        rcfg.dip6[3] += 0x1;
    }

    rcfg.rule_type = 5;
    fill_v6_addr("250::1", rcfg.sip6); 
    for (int i = 0; i < 3125*16; ++i) {
        bloom_add_rule(&rcfg);
        bloom_add_rule(&rcfg);
        rcfg.sip6[3] += 0x1;
    }

}

void testcase_function_v6()
{
    int res;
    bloom_rule_cfg_t rcfg;
    bloom_packet_cfg_t pcfg;
    bloom_clear_all(); 

    rcfg.rule_type = 6;
    fill_v6_addr("100::1", rcfg.dip6); 
    for (int i = 0; i < 1; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x100;
    }


    pcfg.version_type = 6;

    fill_v6_addr("101::1", pcfg.sip6); 
    fill_v6_addr("random", pcfg.dip6); 
    res = debug_match_packet(&pcfg);
    assert(res == 0);
    fill_v6_addr("200::1", pcfg.sip6); 
    res = debug_match_packet(&pcfg);
    assert(res == 1);
    
    //mask rule
    rcfg.rule_type = 7;
    fill_v6_addr("2001::1:1", rcfg.sip6);
    fill_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", rcfg.mask_sip6); 
    fill_v6_addr("0::0", rcfg.mask_dip6);
    //for (int i = 0; i < 12500*16; ++i) {
    for (int i = 0; i < 1; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.dip6[3] += 0x1;
    }
    fill_v6_addr("2001::1:1", pcfg.sip6);
    fill_v6_addr("random", pcfg.dip6); 
    res = debug_match_packet(&pcfg);
    assert(res == 0);
    fill_v6_addr("2101::1:1", pcfg.sip6);
    res = debug_match_packet(&pcfg);
    assert(res == 1);
    fill_v6_addr("2002::1:1", pcfg.sip6);
    res = debug_match_packet(&pcfg);
    assert(res == 0);
}

void testcase_function_v4()
{
    int res;
    bloom_rule_cfg_t rcfg;
    bloom_packet_cfg_t pcfg;
    bloom_clear_all(); 

    rcfg.rule_type = 3;
    rcfg.sip4 = (10<<24)|(50<<16)|(0<<8)|(1);
    rcfg.mask_sip4 = (255<<24)|(255<<16)|(255<<8)|(0);
    rcfg.mask_dip4 = 0;
    for (int i = 0; i < 1; ++i) {
        bloom_add_rule(&rcfg);
        rcfg.sip4 += 0x100;
    }

    pcfg.version_type = 4;
    pcfg.sip4 = (10<<24)|(50<<16)|(0<<8)|(8);
    pcfg.dip4 = (uint32_t)rand();
    res = debug_match_packet(&pcfg);
    assert(res == 0);
    pcfg.sip4 = (10<<24)|(50<<16)|(1<<8)|(8);
    res = debug_match_packet(&pcfg);
    assert(res == 1);
}


int main()
{
    bloom_init();
    testcase_function_v6();
   
    train_v4_mask();
    train_v6_mask();
    train_v4_nomask();
    train_v6_nomask();
    filter_v6(1000000);
    filter_v4(1000000);


    return 0;
}


