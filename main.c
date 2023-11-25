#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <pcap/pcap.h>
#include <ndpi_main.h> // nDPI module
#include <ndpi_typedefs.h>
#include <ndpi_api.h>
// #include <ndpi_config.h>
// #include <ndpi_includes.h>
// #include <ndpi_includes.h>
// #include <ndpi_classify.h>
// #include "/opt/nDPI/src/lib/third_party/include/uthash.h"
// #include "/opt/nDPI/src/lib/third_party/include/ahocorasick.h"

#ifdef __linux__
#include <sched.h>
#endif


#include <rte_common.h>
#include <rte_flow.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_flow.h>


#define RTE_LOGTYPE_DDD RTE_LOGTYPE_USER1
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define MBUF_CACHE_SIZE 256
#define MAX_PKT_BURST 32 
#define max_number_of_flows_in_a_interval 2000
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define max_number_of_flows 2000

#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (uint8_t)(ip >> 24 & 0xff);\
		*b = (uint8_t)(ip >> 16 & 0xff);\
		*c = (uint8_t)(ip >> 8 & 0xff);\
		*d = (uint8_t)(ip & 0xff);\
	} while (0)

static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static volatile bool force_quit;
static int promiscuous_on = 1;
static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        },
};
struct rte_mempool *mbuf_pool = NULL;

/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static unsigned int l2fwd_rx_queue_per_lcore = 2; // RX queues per lcore

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];


struct ipv4_flow{
        rte_be32_t id; // src IP
        int num_packets; // number of packets from this src IP
        rte_be32_t num_sessions; // number of sessions (destination IP) of this srcIP
        uint16_t volume; 
        int cps; // connection per seconds
};


// Comparison function for qsort
int compare(const void *a, const void *b) {
    int *x = (int *)a;
    int *y = (int *)b;
    return *y - *x;
}

int find_max(const int arr[],int arr_size){
        // int arr_len = sizeof(arr) / sizeof(arr[0]);
        int max = arr[0];
        for(int i=0;i<arr_size;i++){
                if (arr[i]>max)
                        max = arr[i];
                // printf("arr[%d]=%d - ",i,arr[i]);
        }
        return max;
}

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = 2;

        const uint16_t tx_rings = 4;
        
        int retval;
        uint16_t q;

        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;
        
        rte_eth_dev_info_get(port, &dev_info);
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
               port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

        /* Configure the Ethernet device. */
        
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
                return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0)
                return retval;

        /* Allocate and set up RX queue per Ethernet port. */ 
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
                if (retval < 0)
                        return retval;
        }
        /* Allocate and set up TX queue per Ethernet port. */ 
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        // Allocate and set up 1 TX queue per Ethernet port.
        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                rte_eth_dev_socket_id(port), &txconf);
                if (retval < 0)
                        return retval;
        }


        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
                return retval;

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        rte_eth_macaddr_get(port, &addr);
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        port,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);

        /* Enable RX in promiscuous mode for the Ethernet device. */
        rte_eth_promiscuous_enable(port);


        printf("Port %u: \n\n", port);

	/* initialize port stats */
	memset(&port_statistics, 0, sizeof(port_statistics));

        return 0;
}

// ndpi definitions

#define MAX_FLOW_ROOTS 2048
#define MAX_IDLE_FLOWS 64
#define TICK_RESOLUTION 1000
#define IDLE_SCAN_PERIOD 10000 // msec
#define MAX_IDLE_TIME 300000 // msec

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

enum nDPI_l3_type {
  L3_IP, L3_IP6
};

struct nDPI_flow_info {
  uint32_t flow_id;
  unsigned long long int packets_processed;
  uint64_t first_seen;
  uint64_t last_seen;
  uint64_t hashval;

  enum nDPI_l3_type l3_type;
  union {
    struct {
      uint32_t src;
      uint32_t pad_00[3];
      uint32_t dst;
      uint32_t pad_01[3];
    } v4;
    struct {
      uint64_t src[2];
      uint64_t dst[2];
    } v6;

    struct {
      uint32_t src[4];
      uint32_t dst[4];
    } u32;
  } ip_tuple;

  unsigned long long int total_l4_data_len;
  uint16_t src_port;
  uint16_t dst_port;

  uint8_t is_midstream_flow:1;
  uint8_t flow_fin_ack_seen:1;
  uint8_t flow_ack_seen:1;
  uint8_t detection_completed:1;
  uint8_t tls_client_hello_seen:1;
  uint8_t tls_server_hello_seen:1;
  uint8_t flow_info_printed:1;
  uint8_t reserved_00:1;
  uint8_t l4_protocol;

  struct ndpi_proto detected_l7_protocol;
  struct ndpi_proto guessed_protocol;

  struct ndpi_flow_struct * ndpi_flow;
};

struct nDPI_workflow {

  volatile long int error_or_eof;

  unsigned long long int packets_captured;
  unsigned long long int packets_processed;
  unsigned long long int total_l4_data_len;
  unsigned long long int detected_flow_protocols;

  uint64_t last_idle_scan_time;
  uint64_t last_time;

  void ** ndpi_flows_active;
  unsigned long long int max_active_flows;
  unsigned long long int cur_active_flows;
  unsigned long long int total_active_flows;

  void ** ndpi_flows_idle;
  unsigned long long int max_idle_flows;
  unsigned long long int cur_idle_flows;
  unsigned long long int total_idle_flows;

  struct ndpi_detection_module_struct * ndpi_struct;
};
struct ndpi_thread {
  struct nDPI_workflow * workflow;
  // pthread_t thread_id;
  // uint32_t array_index;
};
static struct ndpi_thread ndpi_threads[RTE_MAX_LCORE] = {};


static volatile long int flow_id = 0;

// nDPI methods

static void free_workflow(struct nDPI_workflow ** const workflow);

// static struct nDPI_workflow * init_workflow(char const * const file_or_device)
static struct nDPI_workflow * init_workflow()
{
  /*
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  */
  struct nDPI_workflow * workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

  ndpi_init_prefs init_prefs = ndpi_no_prefs;
  workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
  if (workflow->ndpi_struct == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  workflow->total_active_flows = 0;
  workflow->max_active_flows = MAX_FLOW_ROOTS;
  workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
  if (workflow->ndpi_flows_active == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  workflow->total_idle_flows = 0;
  workflow->max_idle_flows = MAX_IDLE_FLOWS;
  workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
  if (workflow->ndpi_flows_idle == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  NDPI_PROTOCOL_BITMASK protos;
  NDPI_BITMASK_SET_ALL(protos);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
  ndpi_finalize_initialization(workflow->ndpi_struct);

  return workflow;
}

static int ip_tuples_compare(struct nDPI_flow_info const * const A, struct nDPI_flow_info const * const B)
{
  // generate a warning if the enum changes
  switch (A->l3_type)
  {
    case L3_IP:
    case L3_IP6:
      break;
  }

  if (A->l3_type == L3_IP && B->l3_type == L3_IP)
  {
    if (A->ip_tuple.v4.src < B->ip_tuple.v4.src)
    {
      return -1;
    }
    if (A->ip_tuple.v4.src > B->ip_tuple.v4.src)
    {
      return 1;
    }
    if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
    {
      return -1;
    }
    if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
    {
      return 1;
    }
  }
  else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
  {
    if (A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1])
    {
      return -1;
    }
    if (A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1])
    {
      return 1;
    }
    if (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1])
    {
      return -1;
    }
    if (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1])
    {
      return 1;
    }
  }

  if (A->src_port < B->src_port)
  {
    return -1;
  }
  if (A->src_port > B->src_port)
  {
    return 1;
  }
  if (A->dst_port < B->dst_port)
  {
    return -1;
  }
  if (A->dst_port > B->dst_port)
  {
    return 1;
  }

  return 0;
}

static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
  struct nDPI_flow_info const * const flow_info_a = (struct nDPI_flow_info *)A;
  struct nDPI_flow_info const * const flow_info_b = (struct nDPI_flow_info *)B;

  if (flow_info_a->hashval < flow_info_b->hashval) {
    return(-1);
  } else if (flow_info_a->hashval > flow_info_b->hashval) {
    return(1);
  }

  /* Flows have the same hash */
  if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
    return(-1);
  } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
    return(1);
  }

  return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void ndpi_flow_info_freer(void * const node)
{
  struct nDPI_flow_info * const flow = (struct nDPI_flow_info *)node;

  ndpi_flow_free(flow->ndpi_flow);
  ndpi_free(flow);
}


static void free_workflow(struct nDPI_workflow ** const workflow)
{
  struct nDPI_workflow * const w = *workflow;

  if (w == NULL) {
    return;
  }

  /*
  if (w->pcap_handle != NULL) {
    pcap_close(w->pcap_handle);
    w->pcap_handle = NULL;
  }
  */

  if (w->ndpi_struct != NULL) {
    ndpi_exit_detection_module(w->ndpi_struct);
  }
  for(size_t i = 0; i < w->max_active_flows; i++) {
    ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
  }
  ndpi_free(w->ndpi_flows_active);
  ndpi_free(w->ndpi_flows_idle);
  ndpi_free(w);
  *workflow = NULL;
}




static int ip_tuple_to_string(struct nDPI_flow_info const * const flow, char * const src_addr_str, size_t src_addr_len, char * const dst_addr_str, size_t dst_addr_len)
{
  switch (flow->l3_type) {
  case L3_IP:
    return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
		     src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
		dst_addr_str, dst_addr_len) != NULL;
  case L3_IP6:
    return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
		     src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
		dst_addr_str, dst_addr_len) != NULL;
  }

  return 0;
}

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
  struct nDPI_workflow * const workflow = (struct nDPI_workflow *)user_data;
  struct nDPI_flow_info * const flow = *(struct nDPI_flow_info **)A;

  (void)depth;

  if (workflow == NULL || flow == NULL) {
    return;
  }

  if (workflow->cur_idle_flows == MAX_IDLE_FLOWS) {
    return;
  }

  if (which == ndpi_preorder || which == ndpi_leaf) {
    if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
	flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
      {
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
	ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
	workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
	workflow->total_idle_flows++;
      }
  }
}

static void check_for_idle_flows(struct nDPI_workflow * const workflow)
{
  if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
    for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
      ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

      while (workflow->cur_idle_flows > 0) {
	struct nDPI_flow_info * const f =
	  (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
	if (f->flow_fin_ack_seen == 1) {
	  printf("Free fin flow with id %u\n", f->flow_id);
	} else {
	  printf("Free idle flow with id %u\n", f->flow_id);
	}
	ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
	ndpi_flow_info_freer(f);
	workflow->cur_active_flows--;
      }
    }

    workflow->last_idle_scan_time = workflow->last_time;
  }
}

static void ndpi_process_packet(struct ndpi_thread *nDPI_thread, struct pcap_pkthdr const * const header, uint8_t const * const packet)
{
  struct ndpi_thread * const reader_thread = (struct ndpi_thread *)nDPI_thread;
  struct nDPI_workflow * workflow;
  struct nDPI_flow_info flow = {};

  size_t hashed_index;
  void * tree_result;
  struct nDPI_flow_info * flow_to_process;

  const struct ndpi_ethhdr * ethernet;
  const struct ndpi_iphdr * ip;
  struct ndpi_ipv6hdr * ip6;

  uint64_t time_ms;
  const uint16_t eth_offset = 0;
  uint16_t ip_offset;
  uint16_t ip_size;

  const uint8_t * l4_ptr = NULL;
  uint16_t l4_len = 0;

  uint16_t type;

  
  workflow = reader_thread->workflow;

  if (workflow == NULL) {
    return;
  }

  workflow->packets_captured++;
  time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
  workflow->last_time = time_ms;

  check_for_idle_flows(workflow);

  /* process datalink layer */
  /*
  switch (pcap_datalink(workflow->pcap_handle)) {
  case DLT_NULL:
    if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002) {
      type = ETH_P_IP;
    } else {
      type = ETH_P_IPV6;
    }
    ip_offset = 4 + eth_offset;
    break;
  case DLT_EN10MB:
  */
    if (header->len < sizeof(struct ndpi_ethhdr)) {
      fprintf(stderr, "[%8llu] Ethernet packet too short - skipping\n",
	      workflow->packets_captured);
      return;
    }
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    type = ntohs(ethernet->h_proto);
    switch (type) {
      case ETH_P_IP: // IPv4
        if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
	        fprintf(stderr, "[%8llu] IP packet too short - skipping\n", workflow->packets_captured);
	        return;
        }
        break;
      case ETH_P_IPV6: // IPV6
        if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
	        fprintf(stderr, "[%8llu] IP6 packet too short - skipping\n", workflow->packets_captured);
	        return;
        }
        break;
      case ETH_P_ARP: // ARP
        return;
      default:
        fprintf(stderr, "[%8llu] Unknown Ethernet packet with type 0x%X - skipping\n", workflow->packets_captured, type);
        return;
    }
    /*
    break;
  default:
    fprintf(stderr, "[%8llu] Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n",
	    workflow->packets_captured, pcap_datalink(workflow->pcap_handle));
    return;
  }
  */

  if (type == ETH_P_IP) {
    ip = (struct ndpi_iphdr *)&packet[ip_offset];
    ip6 = NULL;
  } else if (type == ETH_P_IPV6) {
    ip = NULL;
    ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
  } else {
    fprintf(stderr, "[%8llu] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n",
	    workflow->packets_captured, type);
    return;
  }
  ip_size = header->len - ip_offset;

  if (type == ETH_P_IP && header->len >= ip_offset) {
    if (header->caplen < header->len) {
      fprintf(stderr, "[%8llu] Captured packet size is smaller than packet size: %u < %u\n",
	      workflow->packets_captured, header->caplen, header->len);
    }
  }
  /* process layer3 e.g. IPv4 / IPv6 */
  if (ip != NULL && ip->version == 4) {
    if (ip_size < sizeof(*ip)) {
      fprintf(stderr, "[%8llu] Packet smaller than IP4 header length: %u < %zu\n",
	      workflow->packets_captured, ip_size, sizeof(*ip));
      return;
    }

    flow.l3_type = L3_IP;
    if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
			      &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
      {
	fprintf(stderr, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
		workflow->packets_captured, ip_size - sizeof(*ip));
	return;
      }

    flow.ip_tuple.v4.src = ip->saddr;
    flow.ip_tuple.v4.dst = ip->daddr;
    uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ?
			 flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
  } else if (ip6 != NULL) {
    if (ip_size < sizeof(ip6->ip6_hdr)) {
      fprintf(stderr, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n",
	      workflow->packets_captured, ip_size, sizeof(ip6->ip6_hdr));
      return;
    }

    flow.l3_type = L3_IP6;
    if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
			      &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
      {
	fprintf(stderr, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
		workflow->packets_captured, ip_size - sizeof(*ip6));
	return;
      }

    flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
    flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    uint64_t min_addr[2];
    if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
	flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
      {
	min_addr[0] = flow.ip_tuple.v6.dst[0];
	min_addr[1] = flow.ip_tuple.v6.dst[0];
      } else {
      min_addr[0] = flow.ip_tuple.v6.src[0];
      min_addr[1] = flow.ip_tuple.v6.src[0];
    }
  } else {
    fprintf(stderr, "[%8llu] Non IP/IPv6 protocol detected: 0x%X\n",
	    workflow->packets_captured, type);
    return;
  }

  /* process layer4 e.g. TCP / UDP */
  if (flow.l4_protocol == IPPROTO_TCP) {
    const struct ndpi_tcphdr * tcp;

    if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
      fprintf(stderr, "[%8llu] Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
	      workflow->packets_captured,
	      header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
      return;
    }
    tcp = (struct ndpi_tcphdr *)l4_ptr;
    flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
    flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
    flow.flow_ack_seen = tcp->ack;
    flow.src_port = ntohs(tcp->source);
    flow.dst_port = ntohs(tcp->dest);
  } else if (flow.l4_protocol == IPPROTO_UDP) {
    const struct ndpi_udphdr * udp;

    if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
      fprintf(stderr, "[%8llu] Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
	      workflow->packets_captured,
	      header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
      return;
    }
    udp = (struct ndpi_udphdr *)l4_ptr;
    flow.src_port = ntohs(udp->source);
    flow.dst_port = ntohs(udp->dest);
  }

  
  workflow->packets_processed++;
  workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
  print_packet_info(header, l4_len, &flow);
#endif

  /* calculate flow hash for btree find, search(insert) */
  if (flow.l3_type == L3_IP) {
    if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
			      flow.src_port, flow.dst_port, 0, 0,
			      (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
      {
	flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
      }
  } else if (flow.l3_type == L3_IP6) {
    if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst,
			      flow.src_port, flow.dst_port, 0, 0,
			      (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
      {
	flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
	flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
      }
  }
  flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

  hashed_index = flow.hashval % workflow->max_active_flows;
  tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
  if (tree_result == NULL) {
    /* flow not found in btree: switch src <-> dst and try to find it again */
    uint32_t orig_src_ip[4] = { flow.ip_tuple.u32.src[0], flow.ip_tuple.u32.src[1],
                                flow.ip_tuple.u32.src[2], flow.ip_tuple.u32.src[3] };
    uint32_t orig_dst_ip[4] = { flow.ip_tuple.u32.dst[0], flow.ip_tuple.u32.dst[1],
                                flow.ip_tuple.u32.dst[2], flow.ip_tuple.u32.dst[3] };
    uint16_t orig_src_port = flow.src_port;
    uint16_t orig_dst_port = flow.dst_port;

    flow.ip_tuple.u32.src[0] = orig_dst_ip[0];
    flow.ip_tuple.u32.src[1] = orig_dst_ip[1];
    flow.ip_tuple.u32.src[2] = orig_dst_ip[2];
    flow.ip_tuple.u32.src[3] = orig_dst_ip[3];

    flow.ip_tuple.u32.dst[0] = orig_src_ip[0];
    flow.ip_tuple.u32.dst[1] = orig_src_ip[1];
    flow.ip_tuple.u32.dst[2] = orig_src_ip[2];
    flow.ip_tuple.u32.dst[3] = orig_src_ip[3];

    flow.src_port = orig_dst_port;
    flow.dst_port = orig_src_port;

    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    flow.ip_tuple.u32.src[0] = orig_src_ip[0];
    flow.ip_tuple.u32.src[1] = orig_src_ip[1];
    flow.ip_tuple.u32.src[2] = orig_src_ip[2];
    flow.ip_tuple.u32.src[3] = orig_src_ip[3];

    flow.ip_tuple.u32.dst[0] = orig_dst_ip[0];
    flow.ip_tuple.u32.dst[1] = orig_dst_ip[1];
    flow.ip_tuple.u32.dst[2] = orig_dst_ip[2];
    flow.ip_tuple.u32.dst[3] = orig_dst_ip[3];

    flow.src_port = orig_src_port;
    flow.dst_port = orig_dst_port;
  }

  if (tree_result == NULL) {
    /* flow still not found, must be new */
    if (workflow->cur_active_flows == workflow->max_active_flows) {
      fprintf(stderr, "[%8llu] max flows to track reached: %llu, idle: %llu\n",
	      workflow->packets_captured,
	      workflow->max_active_flows, workflow->cur_idle_flows);
      return;
    }

    flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == NULL) {
      fprintf(stderr, "[%8llu] Not enough memory for flow info\n",
	      workflow->packets_captured);
      return;
    }

    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
    flow_to_process->flow_id = __sync_fetch_and_add(&flow_id, 1);

    flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow_to_process->ndpi_flow == NULL) {
      fprintf(stderr, "[%8llu, %4u] Not enough memory for flow struct\n",
	      workflow->packets_captured, flow_to_process->flow_id);
      return;
    }
    memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    printf("[%8llu, %4u] new %sflow\n", workflow->packets_captured, flow_to_process->flow_id,
	   (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));
    if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL) {
      /* Possible Leak, but should not happen as we'd abort earlier. */
      return;
    }

    workflow->cur_active_flows++;
    workflow->total_active_flows++;
  } else {
    flow_to_process = *(struct nDPI_flow_info **)tree_result;
  }

  flow_to_process->packets_processed++;
  flow_to_process->total_l4_data_len += l4_len;
  /* update timestamps, important for timeout handling */
  if (flow_to_process->first_seen == 0) {
    flow_to_process->first_seen = time_ms;
  }
  flow_to_process->last_seen = time_ms;
  /* current packet is an TCP-ACK? */
  flow_to_process->flow_ack_seen = flow.flow_ack_seen;

  /* TCP-FIN: indicates that at least one side wants to end the connection */
  if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
    flow_to_process->flow_fin_ack_seen = 1;
    printf("[%8llu, %4u] end of flow\n",  workflow->packets_captured,
	   flow_to_process->flow_id);
    return;
  }

  /*
   * This example tries to use maximum supported packets for detection:
   * for uint8: 0xFF
   */
  if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
    return;
  } else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
    /* last chance to guess something, better then nothing */
    uint8_t protocol_was_guessed = 0;
    flow_to_process->guessed_protocol =
      ndpi_detection_giveup(workflow->ndpi_struct,
			    flow_to_process->ndpi_flow,
			    1, &protocol_was_guessed);
    if (protocol_was_guessed != 0) {
      printf("[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
	     workflow->packets_captured,
	     flow_to_process->flow_id,
	     ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol),
	     ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol),
	     ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category));
    } else {
      printf("[%8llu, %4d][FLOW NOT CLASSIFIED]\n",
	     workflow->packets_captured, flow_to_process->flow_id);
    }
  }

  flow_to_process->detected_l7_protocol =
    ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow,
				  ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
				  ip_size, time_ms, NULL);

  if (ndpi_is_protocol_detected(workflow->ndpi_struct,
				flow_to_process->detected_l7_protocol) != 0 &&
      flow_to_process->detection_completed == 0)
    {
      if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
          flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      {
        flow_to_process->detection_completed = 1;
        workflow->detected_flow_protocols++;

        printf("[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
	       workflow->packets_captured,
	       flow_to_process->flow_id,
	       ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
	       ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
	       ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category));
      }
    }

  if (flow_to_process->ndpi_flow->num_extra_packets_checked <=
      flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
      /*
       * Your business logic starts here.
       *
       * This example does print some information about
       * TLS client and server hellos if available.
       *
       * You could also use nDPI's built-in json serialization
       * and send it to a high-level application for further processing.
       *
       * EoE - End of Example
       */

      if (flow_to_process->flow_info_printed == 0)
      {
        char const * const flow_info = ndpi_get_flow_info(flow_to_process->ndpi_flow, &flow_to_process->detected_l7_protocol);
        if (flow_info != NULL)
        {
          printf("[%8llu, %4d] info: %s\n",
            workflow->packets_captured,
            flow_to_process->flow_id,
            flow_info);
          flow_to_process->flow_info_printed = 1;
        }
      }

      if (flow_to_process->detected_l7_protocol.master_protocol == NDPI_PROTOCOL_TLS ||
	  flow_to_process->detected_l7_protocol.app_protocol == NDPI_PROTOCOL_TLS)
        {
	  if (flow_to_process->tls_client_hello_seen == 0 &&
	      flow_to_process->ndpi_flow->protos.tls_quic.hello_processed != 0)
            {
	      uint8_t unknown_tls_version = 0;
	      char buf_ver[16];
	      printf("[%8llu, %4d][TLS-CLIENT-HELLO] version: %s | sni: %s | (advertised) ALPNs: %s\n",
		     workflow->packets_captured,
		     flow_to_process->flow_id,
		     ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
					  flow_to_process->ndpi_flow->protos.tls_quic.ssl_version,
					  &unknown_tls_version),
		     flow_to_process->ndpi_flow->host_server_name,
		     (flow_to_process->ndpi_flow->protos.tls_quic.advertised_alpns != NULL ?
		      flow_to_process->ndpi_flow->protos.tls_quic.advertised_alpns : "-"));
	      flow_to_process->tls_client_hello_seen = 1;
            }
	  if (flow_to_process->tls_server_hello_seen == 0 &&
	      flow_to_process->ndpi_flow->tls_quic.certificate_processed != 0)
            {
	      uint8_t unknown_tls_version = 0;
	      char buf_ver[16];
	      printf("[%8llu, %4d][TLS-SERVER-HELLO] version: %s | common-name(s): %.*s | "
		     "issuer: %s | subject: %s\n",
		     workflow->packets_captured,
		     flow_to_process->flow_id,
		     ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
					  flow_to_process->ndpi_flow->protos.tls_quic.ssl_version,
					  &unknown_tls_version),
		     (flow_to_process->ndpi_flow->protos.tls_quic.server_names_len == 0 ?
		      1 : flow_to_process->ndpi_flow->protos.tls_quic.server_names_len),
		     (flow_to_process->ndpi_flow->protos.tls_quic.server_names == NULL ?
		      "-" : flow_to_process->ndpi_flow->protos.tls_quic.server_names),
		     (flow_to_process->ndpi_flow->protos.tls_quic.issuerDN != NULL ?
		      flow_to_process->ndpi_flow->protos.tls_quic.issuerDN : "-"),
		     (flow_to_process->ndpi_flow->protos.tls_quic.subjectDN != NULL ?
		      flow_to_process->ndpi_flow->protos.tls_quic.subjectDN : "-"));
	      flow_to_process->tls_server_hello_seen = 1;
            }
        }
    }
}



/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port, and do processing on the metrics.
 */
static int lcore_main(__rte_unused void *dummy){  
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  unsigned int i,j, port, lcore_id, nb_rx, nb_tx;
  struct lcore_queue_conf *qconf;
  struct ipv4_flow flow_stats[max_number_of_flows];
  lcore_id = rte_lcore_id();
  qconf = &lcore_queue_conf[lcore_id];

  if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, DDD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, DDD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {
		port = qconf->rx_port_list[i];
		RTE_LOG(INFO, DDD, " -- lcoreid=%u portid=%u\n", lcore_id, port);

	}
  ndpi_threads[lcore_id].workflow = init_workflow();
        clock_t start_time, end_time;
        double time_elapsed;
        int window_size = 10;
        int window_buffer[window_size];
        int interval_buffer[max_number_of_flows_in_a_interval];
        for (int ii = 0; ii < max_number_of_flows_in_a_interval; ii++)
                interval_buffer[ii] = 0;
        int c = 0; // interval counter
        struct rte_ipv4_hdr *ipv4_hdr;
        struct rte_mbuf *pkt;
        int p = 1; // training phases
        int cp = 0;
        int v_max = 0;
        int v_min = 3000;
        bool training = true;      
        i=0;
        double r_var,r_l,r_mean,r_sd,r_u;
        int sum,number_of_packets_in_a_interval,window_sum,v_act,r_size=0,r_sum=0;
        double window_throughput,v_pred=0,r_pred=0;
        while(!force_quit){        
                start_time = clock();
                end_time = clock();
                number_of_packets_in_a_interval = 0;
                // interval_buffer = (unsigned int *) malloc (max_number_of_flows_in_a_interval * sizeof(unsigned int));
                sum = 0;
                window_sum = 0;
                window_throughput = 0;
                v_act = 0;
                v_pred = 0;
                
                
                // training
                while(cp<p && training){
                        sum = 0;
                        start_time = clock();
                        end_time = clock();
                        while(((end_time - start_time) / CLOCKS_PER_SEC)<1){
                                // recieving packets
                                for (i = 0; i < qconf->n_rx_port; i++) {
                                        port = qconf->rx_port_list[i];
                                        nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST);
                                        if (unlikely(nb_rx == 0))
                                                continue;
                                        port_statistics[port].rx += nb_rx;
                                        // processing packets
                                        for (j = 0; j < nb_rx; j++) {
                                                pkt = pkts_burst[j];
                                                ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                                                interval_buffer[ipv4_hdr->dst_addr % max_number_of_flows_in_a_interval]++;
                                                
                                                uint16_t packetLength = rte_pktmbuf_pkt_len(pkt);
                                                uint16_t payloadLength = packetLength - pkt->l2_len - pkt->l3_len - pkt->l4_len;
                                                flow_stats[ipv4_hdr->src_addr % max_number_of_flows].num_packets++;
                                                flow_stats[ipv4_hdr->src_addr % max_number_of_flows].volume+=payloadLength;

                                                char *data = rte_pktmbuf_mtod(pkt, char *);
                                                int len = rte_pktmbuf_pkt_len(pkt);
                                                struct pcap_pkthdr h;
                                                h.len = h.caplen = len;
                                                gettimeofday(&h.ts, NULL);
                                                ndpi_process_packet(&ndpi_threads[lcore_id],&h, (const u_char *)data);
                                                
                                        }
                                        
                                        // sending packets back
                                        nb_tx = rte_eth_tx_burst(port ^ 1, 0, pkts_burst, nb_rx);
			                /* Free any unsent packets. */
			                if (unlikely(nb_tx < nb_rx)) {
				                uint16_t buf;
				                for (buf = nb_tx; buf < nb_rx; buf++)
					                rte_pktmbuf_free(pkts_burst[buf]);
			                }
                                        
                                        
                                        number_of_packets_in_a_interval += nb_rx;
                                }
                                end_time = clock();
                        }
                        
                        // a time interval passed
                        
                        printf("Number of packets in %d time interval: %d\n",c,number_of_packets_in_a_interval);
                        number_of_packets_in_a_interval = 0;
                        /*
                        for(int s=0;s<max_number_of_flows;s++){
                                char a,b,c,d;
                                uint32_t_to_char(rte_bswap32(ipv4_hdr->src_addr), &a, &b, &c, &d);
                                printf("%3hhu.%3hhu.%3hhu.%3hhu\t %d %d",a,b,c,d,flow_stats[s].num_packets,flow_stats[s].volume); 
                        }
                        */
                        // system("clear");
                        // find max through in current interval
                        /*
                        for(int t=0;t<max_number_of_flows_in_a_interval;t++)
                                printf("%d\t",interval_buffer[t]);
                        */
                        window_buffer[c] = find_max(interval_buffer,max_number_of_flows_in_a_interval);
                        window_sum += window_buffer[c];
                        // free(interval_buffer);
                        for (int ii = 0; ii < max_number_of_flows_in_a_interval; ii++)
                                interval_buffer[ii] = 0;
                        ++c;
                        if ((c%window_size)==0){
                                // window size reached
                                // printf("a window endedd\n");
                                for(int t=0;t<window_size;t++){
                                        // WMA algorithm on current window
                                        window_throughput += window_buffer[t] * ((double)window_buffer[t] / (double)window_sum);
                                }
                                // printf("window %d througput = %f\n",cp,window_throughput);
                                if (window_throughput > v_max)
                                        v_max = window_throughput;
                                if(window_throughput < v_min)
                                        v_min = window_throughput;
                                window_throughput = 0;
                                window_sum = 0;
                                c=0;
                                cp++;
                        }
                        
                }

                
                  

                if(training==true){
                        printf("#####\n#####\ntraining phase finished: \n");
                        c = 0;
                        training = false;
                        printf("v_max = %i\n",v_max);
                        printf("v_min = %i\n",v_min);
                }
                printf("current active flows for %u : %llu \n",lcore_id,ndpi_threads[lcore_id].workflow->cur_active_flows);
                start_time = clock();
                end_time = clock();
                // testing
                while(((end_time - start_time) / CLOCKS_PER_SEC)<1){
                        // recieving packets
                        for (i = 0; i < qconf->n_rx_port; i++) {
                                port = qconf->rx_port_list[i];
                                nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST);
                                if (unlikely(nb_rx == 0))
                                        continue;
                                port_statistics[port].rx += nb_rx;
                                // processing packets
                                for (j = 0; j < nb_rx; j++) {
                                        pkt = pkts_burst[j];
                                        ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                                        interval_buffer[ipv4_hdr->dst_addr % max_number_of_flows_in_a_interval]++;
                                        
                                                uint16_t packetLength = rte_pktmbuf_pkt_len(pkt);
                                                uint16_t payloadLength = packetLength - pkt->l2_len - pkt->l3_len - pkt->l4_len;
                                                flow_stats[ipv4_hdr->src_addr % max_number_of_flows].num_packets++;
                                                flow_stats[ipv4_hdr->src_addr % max_number_of_flows].volume+=payloadLength;

                                                char *data = rte_pktmbuf_mtod(pkt, char *);
                                                int len = rte_pktmbuf_pkt_len(pkt);
                                                struct pcap_pkthdr h;
                                                h.len = h.caplen = len;
                                                gettimeofday(&h.ts, NULL);
                                                ndpi_process_packet(&ndpi_threads[lcore_id],&h, (const u_char *)data);
                                                // printf("current active flows for %u : %llu \n",lcore_id,ndpi_threads[i].workflow->total_active_flows);
                                }

                                // sending packets back
                                nb_tx = rte_eth_tx_burst(port ^ 1, 0, pkts_burst, nb_rx);
			        /* Free any unsent packets. */
			        if (unlikely(nb_tx < nb_rx)) {
				        uint16_t buf;
				        for (buf = nb_tx; buf < nb_rx; buf++)
				                rte_pktmbuf_free(pkts_burst[buf]);
			        }

                                number_of_packets_in_a_interval += nb_rx;
                        }
                        end_time = clock();
                }
                // a time interval passed
                printf("Number of packets in current time interval: %u\n",number_of_packets_in_a_interval);
                
                
                
                // calculate WMA predict for next interval
                qsort(&interval_buffer, max_number_of_flows_in_a_interval, sizeof(int), compare);
                // WMA algorithm on current window
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                        if (interval_buffer[t]>0)                        
                                v_pred += interval_buffer[t] * ((double)interval_buffer[t]/(double)number_of_packets_in_a_interval);
                        else
                                break;
                }
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                        // calculate Ratio Metric
                        r_pred = interval_buffer[t] / v_pred;
                        // printf("r_pred = %f\n",r_pred);
                        r_size += r_pred>0?1:0;
                        r_sum += r_pred;
                }
                // calcuate mean and sd for Ratio Metric
                
                if(r_size<0)
                        r_mean = r_sum / r_size;
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                        r_pred = interval_buffer[t] / v_pred;
                        if (r_pred>0)
                                r_var += pow(r_pred-r_mean,2);
                }
                r_var /= r_size;
                r_sd = sqrt(r_var); 
                r_u = r_mean + 3 * r_sd;
                r_l = r_mean - 3 * r_sd;
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                        // alert DDoS detection
                        if ((r_pred > r_u && interval_buffer[t]>v_max) || (r_pred < r_l && interval_buffer[t] < v_min))
                                printf("A ddos has been occured");
                        //else
                }
                number_of_packets_in_a_interval = 0;
                r_size = 0;
                r_var = 0;
                v_pred = 0;
                r_sum=0;
                c++;
                // free(interval_buffer);
                for (int ii = 0; ii < number_of_packets_in_a_interval; ii++)
                        interval_buffer[i] = 0;
                if (c%window_size==0) // window size reached
                        c=0;
                
        }

        return 0;
}



static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int main(int argc, char *argv[]){
  
  struct lcore_queue_conf *qconf=NULL;
  unsigned nb_ports;
  uint16_t portid;
  unsigned lcore_id, rx_lcore_id=0;
  unsigned int nb_lcores = 0;


  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  
  argc -= ret;
  argv += ret;
  
  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGINT, signal_handler);
  
  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports==0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports\n");

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 || lcore_queue_conf[rx_lcore_id].n_rx_port == l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}


        
  /* Creates a new mbuf mempool in memory to hold the mbufs objects (that store packets).
  containts NUM_MBUFS * nb_ports of mbuf pkts in it with each of them's size is RTE_MBUF_DEFAULT_BUF_SIZE
  a cache of 
  Each lcore cache will be MBUF_CACHE_SIZE
  number of mbuf pkts */
  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",RTE_MAX((nb_rxd + 0 + MAX_PKT_BURST + nb_lcores * MBUF_CACHE_SIZE) * nb_ports,8192u),MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  
  /* Initialize all ports. */
  RTE_ETH_FOREACH_DEV(portid){
    if (port_init(portid, mbuf_pool) != 0)
      rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
  }
        
  ret = 0;

  /* launch per-lcore init on every lcore also on main lcore */
  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);      
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
       
  // closing ports
  RTE_ETH_FOREACH_DEV(portid){
    printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
  }

  for(unsigned int li=0;li<RTE_MAX_LCORE;li++){
    qconf = &lcore_queue_conf[li];
    if (qconf->n_rx_port != 0) {
      printf("current active flows for %u : %llu \n",li,ndpi_threads[li].workflow->cur_active_flows);
    }
  }

  // Clean-up EAL
  rte_eal_cleanup();
  
  printf("Bye...\n");
        
  return ret;
}