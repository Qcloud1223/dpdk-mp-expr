#ifndef _HASH_H
#define _HASH_H

#include <stdint.h>
#include <rte_hash.h>

struct rte_hash *setup_hash();
uint16_t em_get_ipv4_dst_port(void *ipv4_hdr, struct rte_hash *flow_table);

#endif