/* Hash utilities shared by naive S-RSS and RSSpp */
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include <rte_hash.h>
// for xmm_t
#include <rte_vect.h>
#include <rte_hash_crc.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "hash.h"
// for num_clients
#include "init.h"

#define NB_SOCKETS 8
#define L3FWD_HASH_ENTRIES		(1024*1024*4)

// treat ipv4 header as a xmm register, and decide the element to hash
// by using mask
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static rte_xmm_t mask0 = (rte_xmm_t){
	.u32 = {
		// ignore TTL and checksum, keep protocol
		BIT_8_TO_15,
		// keep src and dst IP
		ALL_32_BITS,
		ALL_32_BITS,
		// keep src and dst port
		ALL_32_BITS} 
};

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __rte_packed;

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

struct rte_hash *ipv4_l3fwd_em_lookup_struct[NB_SOCKETS];
// TODO: support dynamic worker count
static uint32_t flow_cnt;

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

    // TODO: check if crc is enabled on machine
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);

	return init_val;
}

// traverse a pcap and fill its packets into the hash table
void fill_hash_table_from_trace(const char *pcap)
{

}

/* largely borrowed from examples/l3fwd/l3fwd_em.c */
struct rte_hash *setup_hash()
{
    struct rte_hash_parameters ipv4_l3fwd_hash_params = {
		.name = NULL,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
	};

    // TODO: add ipv6 support
	
    char s[64];
    unsigned socketid = rte_socket_id();
    /* create ipv4 hash */
    // WARNING: careful when deciding the core running server/client
    // since they might be on separate sockets
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socketid);
	ipv4_l3fwd_hash_params.name = s;
	ipv4_l3fwd_hash_params.socket_id = socketid;
	ipv4_l3fwd_em_lookup_struct[socketid] =
		rte_hash_create(&ipv4_l3fwd_hash_params);
	if (ipv4_l3fwd_em_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd hash on socket %d\n",
			socketid);

	/* Note that DPDK use populate_ipv4_many_flow_into_table to generate random flow entries
	 * which is quite arbitrary
	 * A better approach would be filling the packets from a pcap into the hash table,
	 * so that there won't be any runtime lookup miss
	 */
	fill_hash_table_from_trace(NULL);

	return ipv4_l3fwd_em_lookup_struct[socketid];
}

// WARNING: This code is runs w/o problem on most Intel machines in lab,
// but is definitely not compatible with ARM chips, i.e. Huawei Kunpeng.
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}

// The destination of each flow
static uint8_t ipv4_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;
// TODO: add statistic for each flow, so that we can estimate workload

// Routing information of each flow
struct ipv4_l3fwd_em_route {
	struct ipv4_5tuple key;
	uint8_t if_out;
};

static void
convert_ipv4_5tuple_to_be(struct ipv4_5tuple *key1,
		union ipv4_5tuple_host *key2)
{
	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
}

static void
convert_ipv4_5tuple(struct ipv4_5tuple *key1,
		union ipv4_5tuple_host *key2)
{
	key2->ip_dst = key1->ip_dst;
	key2->ip_src = key1->ip_src;
	key2->port_dst = key1->port_dst;
	key2->port_src = key1->port_src;
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
}

static void print128_num(__m128i var) 
{
    int64_t v64val[2];
    memcpy(v64val, &var, sizeof(v64val));
    printf("%.16lx %.16lx\n", v64val[1], v64val[0]);
}

/* minor changes: hard code lookup_struct */
uint16_t
em_get_ipv4_dst_port(void *ipv4_hdr, struct rte_hash *flow_table)
{
	int ret = 0;
	union ipv4_5tuple_host key;

	struct rte_ipv4_hdr *real_ipv4_hdr = ipv4_hdr;
	struct rte_tcp_hdr  *real_tcp_hdr  = (struct rte_tcp_hdr *)((char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));

	// move the pointer to TTL, for later xmm loading
	ipv4_hdr = (uint8_t *)ipv4_hdr +
		offsetof(struct rte_ipv4_hdr, time_to_live);

	/*
	 * Get 5 tuple: dst port, src port, dst IP address,
	 * src IP address and protocol.
	 */
	key.xmm = em_mask_key(ipv4_hdr, mask0.x);

	/* Find destination port */
	ret = rte_hash_lookup(flow_table, (const void *)&key);
	
	#ifdef DEBUG
	printf("lookup key: ");
	print128_num(key.xmm);
	printf("return value: %d\n", ret);
	rte_delay_ms(200);
	#endif

	// TODO: profile if runtime adding key has a large overhead
	// if so, change this
	if (ret == -ENOENT) {
		// TODO: check if this is actual adding the same five_tuple
		// since xmm seems to have different endianness
		struct ipv4_l3fwd_em_route entry;
		union ipv4_5tuple_host newkey;
		// here, what we've derived from the packet is already big endian
		// so no need to convert them
		entry.key.proto = real_ipv4_hdr->next_proto_id;
		entry.key.ip_src = real_ipv4_hdr->src_addr;
		entry.key.ip_dst = real_ipv4_hdr->dst_addr;
		entry.key.port_src = real_tcp_hdr->src_port;
		entry.key.port_dst = real_tcp_hdr->dst_port;
		// Round Robin the flows, instead of the packets
		entry.if_out = (flow_cnt++) % num_clients;

		convert_ipv4_5tuple(&entry.key, &newkey);
		int addret = rte_hash_add_key(flow_table, (void *) &newkey);
		if (addret < 0) {
			fprintf(stderr, "Cannot add elements to hash table, is it full?\n");
			exit(-1);
		}
		ipv4_l3fwd_out_if[addret] = entry.if_out;
		#ifdef DEBUG
		unsigned char *sip = (unsigned char *)(&entry.key.ip_src);
		unsigned char *dip = (unsigned char *)(&entry.key.ip_dst);
		printf("sip: %u.%u.%u.%u, dip: %u.%u.%u.%u, sport: %d, dport: %d, proto: %d, key: ", 
			*sip, *(sip + 1), *(sip + 2), *(sip + 3),
			*dip, *(dip + 1), *(dip + 2), *(dip + 3),
			entry.key.port_src,
			entry.key.port_dst,
			entry.key.proto);
		print128_num(newkey.xmm);
		printf("interface out: %d\n", entry.if_out);
		rte_delay_ms(200);
		#endif
	} else if (ret < 0) {
		fprintf(stderr, "invalid hash lookup argument\n");
		exit(-1);
	}

	return ipv4_l3fwd_out_if[ret];
}