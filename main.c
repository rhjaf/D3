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
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <pcap/pcap.h>
#include <ndpi_main.h> // nDPI module

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

#define TICK_RESOLUTION 1000
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

// nDPI

static struct ndpi_detection_module_struct *ndpi_struct = NULL;

/*
static void setupDetection(void)
{
    u_int32_t i;
    NDPI_PROTOCOL_BITMASK all;

    // init global detection structure
    if (ndpi_struct == NULL) {
        printf("ERROR: global structure initialization failed\n");
        exit(-1);
    }
    
    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

    // allocate memory for id and flow tracking
    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    osdpi_ids = malloc(MAX_OSDPI_IDS * sizeof(struct osdpi_id));
    if (osdpi_ids == NULL) {
        printf("ERROR: malloc for osdpi_ids failed\n");
        exit(-1);
    }
    for (i = 0; i < MAX_OSDPI_IDS; i++) {
        memset(&osdpi_ids[i], 0, sizeof(struct osdpi_id));
        osdpi_ids[i].ndpi_id = calloc(1, size_id_struct);
        if (osdpi_ids[i].ndpi_id == NULL) {
            printf("ERROR: malloc for ndpi_id_struct failed\n");
            exit(-1);
        }
    }

    osdpi_flows = malloc(MAX_OSDPI_FLOWS * sizeof(struct osdpi_flow));
    if (osdpi_flows == NULL) {
        printf("ERROR: malloc for osdpi_flows failed\n");
        exit(-1);
    }
    for (i = 0; i < MAX_OSDPI_FLOWS; i++) {
        memset(&osdpi_flows[i], 0, sizeof(struct osdpi_flow));
        osdpi_flows[i].ndpi_flow = calloc(1, size_flow_struct);
        if (osdpi_flows[i].ndpi_flow == NULL) {
            printf("ERROR: malloc for ndpi_flow_struct failed\n");
            exit(-1);
        }
    }

    // clear memory for results
    memset(protocol_counter, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
    memset(protocol_counter_bytes, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
    
}

*/

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

// nDPI
/*
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


static void classify(mbuf *pkt){
        struct ndpi_detection_module_struct * ndpi_struct = NULL;
        ndpi_init_prefs init_prefs = ndpi_no_prefs;
        ndpi_struct = ndpi_init_detection_module(init_prefs);
        if (ndpi_struct == NULL) {
                free_workflow(&workflow);
                return NULL;
        }

        NDPI_PROTOCOL_BITMASK protos;
        NDPI_BITMASK_SET_ALL(protos);
        ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protos);

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
        uint32_t thread_index = INITIAL_THREAD_HASH; // generated with `dd if=/dev/random bs=1024 count=1 |& hd'

        time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
        // process datalink layer
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
                        if (header->len < sizeof(struct ndpi_ethhdr)) {
                                fprintf(stderr, "[%8llu, %d] Ethernet packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
                        return;
                        }
                        ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
                        ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
                        type = ntohs(ethernet->h_proto);
                        switch (type) {
                                case ETH_P_IP: // IPv4 
                                        if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                                                fprintf(stderr, "[%8llu, %d] IP packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
                                                return;
                                        }
                                        break;
                                case ETH_P_IPV6: // IPV6 
                                        if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                                                fprintf(stderr, "[%8llu, %d] IP6 packet too short - skipping\n",workflow->packets_captured, reader_thread->array_index);
                                                return;
                                        }
                                        break;
                                case ETH_P_ARP: // ARP 
                                        return;
                                default:
                                        fprintf(stderr, "[%8llu, %d] Unknown Ethernet packet with type 0x%X - skipping\n",workflow->packets_captured, reader_thread->array_index, type);
                                        return;
                        }
                        break;
                default:
                        fprintf(stderr, "[%8llu, %d] Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n",workflow->packets_captured, reader_thread->array_index, pcap_datalink(workflow->pcap_handle));
                        return;
        }



        ndpi_finalize_initialization(ndpi_struct);
}
*/
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = 2;

        const uint16_t tx_rings = 2;
        
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

static void ndpi_process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
                                        
                                        
                                        return ;
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
                                                ndpi_process_packet(&h, (const u_char *)data);
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

int main(int argc, char *argv[])
{

        struct lcore_queue_conf *qconf;
        unsigned nb_ports;
        uint16_t portid;
        unsigned lcore_id, rx_lcore_id;
        unsigned int nb_lcores = 0;
        
        
        // setupDetection(); // nDPI initalizationx

        /* Initialize the Environment Abstraction Layer (EAL). */
        int ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");


        argc -= ret;
        argv += ret;

        force_quit = false;
        signal(SIGINT, signal_handler);
        signal(SIGINT, signal_handler);
        
        
        rx_lcore_id = 0;
	qconf = NULL;

        nb_ports = rte_eth_dev_count_avail();
        if (nb_ports==0)
                rte_exit(EXIT_FAILURE, "No Ethernet ports\n");



	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
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
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
        }

        // Clean-up EAL
        rte_eal_cleanup();
        printf("Bye...\n");
        
        return ret;
}