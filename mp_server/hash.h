#ifndef _HASH_H
#define _HASH_H

#include <stdint.h>
#include <rte_hash.h>

extern unsigned worker_cnt;

void setup_hash();
uint16_t em_get_ipv4_dst_port(void *ipv4_hdr, uint16_t portid, struct rte_hash *flow_table);

#endif