#include "bloom_filter.h"


uint8_t bloom_rule_prefilter_enable = 0;
uint8_t *bloom_bitmap;

typedef struct {
    uint32_t rule_count;
    uint64_t miss_count;
    uint64_t match_count;
}bloom_filter_stat_t;

bloom_filter_stat_t bloom_filter_stat;

static int __bloom_add_rule_mask_recursion(uint8_t *map, uint32_t val, uint32_t mask, int depth)
{
    uint32_t shift_val = 1;
    int i = 0;
    for (; i < 8; ++i, shift_val <<= 1) {
        if (!(mask & shift_val)) {
            if (depth > 7) {
                /*limit recursion depth*/
                /*declare failure*/
                bloom_rule_prefilter_enable = 0;
                return -1;
            }
            __bloom_add_rule_mask_recursion(map, val, mask|shift_val, depth+1);
            __bloom_add_rule_mask_recursion(map, val|shift_val, mask|shift_val, depth+1);
            return 0;
        }
    }
    /*all ones mask*/
    __bloom_insert(map, val);
    return 0;
}

int bloom_add_rule(bloom_rule_cfg_t *cfg)
{
    if (!bloom_rule_prefilter_enable) return -1;
    if (!cfg) return -1;

    uint8_t hash_type = 0;/*0:sip+dip, 1:sip, 2:dip*/
    if (cfg->rule_type > 3) {/*ipv6 -> ipv4*/
        cfg->sip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->sip6);
        cfg->dip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->dip6);
        if (cfg->rule_type == 7)/*ipv6 mask*/
        {
            cfg->mask_sip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->mask_sip6);
            cfg->mask_dip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->mask_dip6);
        }
        cfg->rule_type -= 4;
    }

    uint32_t val = 0, mask = 0;
    uint32_t mask0_sim, mask1_sim, mask2_sim; 
    if (cfg->rule_type == 0) {
        hash_type = 0;
    } else if (cfg->rule_type == 1) {
        hash_type = 1;
    } else if (cfg->rule_type == 2) {
        hash_type = 2;
    } else { /*mask rule*/
        mask0_sim = BLOOM_CFG_IP_ADDR_HASH0(cfg->mask_sip4, cfg->mask_dip4) | 0xff000000;
        mask1_sim = BLOOM_CFG_IP_ADDR_HASH1(cfg->mask_sip4, cfg->mask_dip4) | 0xff000000;
        mask2_sim = BLOOM_CFG_IP_ADDR_HASH2(cfg->mask_sip4, cfg->mask_dip4) | 0xff000000;
        if (__bloom_val_count_one(mask0_sim) > __bloom_val_count_one(mask1_sim)) {
            if (__bloom_val_count_one(mask0_sim) > __bloom_val_count_one(mask2_sim))
                hash_type = 0;
            else
                hash_type = 2;
        } else {
            if (__bloom_val_count_one(mask1_sim) > __bloom_val_count_one(mask2_sim))
                hash_type = 1;
            else
                hash_type = 2;
        }
    }

    if (hash_type == 0) {
        val = BLOOM_CFG_IP_ADDR_HASH0(cfg->sip4, cfg->dip4);
        mask = mask0_sim;
    } else if (hash_type == 1) {
        val = BLOOM_CFG_IP_ADDR_HASH1(cfg->sip4, cfg->dip4);
        mask = mask1_sim;
    } else {
        val = BLOOM_CFG_IP_ADDR_HASH2(cfg->sip4, cfg->dip4);
        mask = mask2_sim;
    }

    if (cfg->rule_type == 3) {
        val &= mask;
        __bloom_add_rule_mask_recursion(bloom_bitmap, val, mask, 0);
    } else {
        __bloom_insert(bloom_bitmap, val);
    } 
    
    bloom_filter_stat.rule_count++;
    return 0;
}

/**
 * @brief check if packet matches any rules 
 *
 * @param cfg
 *
 * @return 1 if no rule matches and the packet can be delivered directly, 0 if may hit a rule, -1 on error 
 */
int bloom_filter_packet_nomatch(bloom_packet_cfg_t *cfg)
{
    if (!bloom_rule_prefilter_enable) return 0;
    if (!cfg) return -1;
    if (cfg->version_type == 6) {
        cfg->sip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->sip6);
        cfg->dip4 = BLOOM_CFG_IP_ADDR_6TO4(cfg->dip6);
    }

    bloom_filter_stat.match_count++;
    uint32_t val;
    val = BLOOM_CFG_IP_ADDR_HASH0(cfg->sip4, cfg->dip4);
    if (__bloom_contain(bloom_bitmap, val) == 0) {
        return 0;
    }

    val = BLOOM_CFG_IP_ADDR_HASH1(cfg->sip4, cfg->dip4);
    if (__bloom_contain(bloom_bitmap, val) == 0) {
        return 0;
    }

    val = BLOOM_CFG_IP_ADDR_HASH2(cfg->sip4, cfg->dip4);
    if (__bloom_contain(bloom_bitmap, val) == 0) {
        return 0;
    }
    
    bloom_filter_stat.miss_count++;
    return 1;
}

void bloom_show_statistics()
{
    double miss_rate = 0;
    if (bloom_filter_stat.match_count) miss_rate = bloom_filter_stat.miss_count *100.0/ bloom_filter_stat.match_count;
    printf("%s: rule count %u, packets count %lu, miss %lu(%.6f %% )\n", 
            __FUNCTION__, 
            (unsigned)bloom_filter_stat.rule_count, 
            (unsigned long)bloom_filter_stat.match_count, 
            (unsigned long)bloom_filter_stat.miss_count, miss_rate);
}

void bloom_clear_all()
{
    if (bloom_rule_prefilter_enable)
        memset(bloom_bitmap, 0, BLOOM_BITMAP_LEN);

    bloom_filter_stat.rule_count = 0;
    bloom_filter_stat.miss_count = 0;
    bloom_filter_stat.match_count = 0;
}

int bloom_init()
{
    bloom_bitmap = (uint8_t*)malloc(BLOOM_BITMAP_LEN);
    if (bloom_bitmap) {
        bloom_rule_prefilter_enable = 1;
        bloom_clear_all();
    } else {
        bloom_rule_prefilter_enable = 0;
    }
    return 0;
}

#ifdef BLOOM_MODULE_TEST
int main()
{
    bloom_init();

    bloom_rule_cfg_t rcfg;
    bloom_packet_cfg_t pcfg;

    rcfg.rule_type = 0;
    rcfg.sip4 = 6<<24;
    rcfg.dip4 = 7<<24;
    bloom_add_rule(&rcfg);
    pcfg.version_type = 4;
    pcfg.sip4 = 6<<24;
    pcfg.dip4 = 7<<24;
    assert(bloom_filter_packet_nomatch(&pcfg) == 0);
    pcfg.dip4 = 8<<24;
    assert(bloom_filter_packet_nomatch(&pcfg) == 1);
    rcfg.rule_type = 1;
    bloom_add_rule(&rcfg);
    assert(bloom_filter_packet_nomatch(&pcfg) == 0);

    return 0;
}
#endif


