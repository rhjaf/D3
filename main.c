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

#include <rte_common.h>
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


#define RTE_LOGTYPE_DDD RTE_LOGTYPE_USER1
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define MBUF_CACHE_SIZE 256
#define MAX_PKT_BURST 32 
#define max_number_of_flows_in_a_interval 200

static uint16_t nb_rxd = RX_DESC_DEFAULT;
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


// Comparison function for qsort
int compare(const void *a, const void *b) {
    int *x = (int *)a;
    int *y = (int *)b;
    return *x - *y;
}

int find_max(const unsigned int *arr){
        int arr_len = sizeof(arr) / sizeof(arr[0]);
        int max = arr[0];
        for(int i=0;i<arr_len;i++)
                max = arr[i]>max?arr[i]:max;
        return max;
}

 
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = 1;
        int retval;
        uint16_t q;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;
        
        /* Configure the Ethernet device. */
        // number of tx rings set to zero
        retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
        if (retval != 0)
                return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, 0);
        if (retval != 0)
                return retval;

        /* Allocate and set up 1 RX queue per Ethernet port. */ 
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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


/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port, and do processing on the metrics.
 */
static int lcore_main(__rte_unused void *dummy){

        
        struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
        struct rte_mbuf *m;
        unsigned i,j, port, lcore_id, nb_rx;
       	struct lcore_queue_conf *qconf;

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
        unsigned int* interval_buffer;
        int c = 0; // interval counter
        struct rte_ipv4_hdr *ipv4_hdr;
        struct rte_mbuf *pkt;
        int p = 100; // training phases
        int v_max = 0;
        int v_min = INT_MAX;
        bool training = true;      
        i=0;
        double r_var,r_l,r_mean,r_sd,r_u;
        int sum,number_of_packets_in_a_interval,window_sum,window_throughput,v_act,v_pred,r_pred,r_size=0,r_sum=0;
        while(!force_quit){        
                start_time = clock();
                end_time = clock();
                number_of_packets_in_a_interval = 0;
                interval_buffer = (int *) malloc (max_number_of_flows_in_a_interval * sizeof(unsigned int));
                sum = 0;
                window_sum = 0;
                window_throughput = 0;
                v_act = 0;
                v_pred = 0;
                

                // training
                while(c<p && training){
                        sum = 0;
                        while((((double) (end_time - start_time)) / CLOCKS_PER_SEC)<1){
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
                                        number_of_packets_in_a_interval += nb_rx;
                                }
                                end_time = clock();
                        }
                        
                        // a time interval passed
                        printf("Number of packets in current time interval: %u\n",number_of_packets_in_a_interval);
                        number_of_packets_in_a_interval = 0;
                        // find max through in current interval
                        window_buffer[c] = find_max(interval_buffer);
                        window_sum += window_buffer[c];
                        c++;
                        if (c%window_size==0){
                                // window size reached
                                for(int t=0;t<window_size;t++)
                                        // WMA algorithm on current window
                                        window_throughput += window_buffer[t] * (window_buffer[t] / window_sum);
                                if (window_throughput > v_max)
                                        v_max = window_throughput;
                                else if(window_throughput < v_min)
                                        v_min = window_throughput;
                                window_throughput = 0;
                                window_sum = 0;
                                c=0;
                        }
                }
                
                if (training == true){
                        printf("#####\n#####\ntraining phase finished: \n");
                        c = 0;
                        training = false;
                        printf("v_max = %i\n",v_max);
                        printf("v_min = %i\n",v_min);
                }
                

                // testing
                while(((((double) (end_time - start_time)) / CLOCKS_PER_SEC)<1) && !training){
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
                                number_of_packets_in_a_interval += nb_rx;
                        }
                        end_time = clock();
                }
                // a time interval passed
                printf("Number of packets in current time interval: %u\n",number_of_packets_in_a_interval);
                
                // calculate WMA predict for next interval
                qsort(interval_buffer, max_number_of_flows_in_a_interval, sizeof(unsigned int), compare);
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                                        // WMA algorithm on current window
                                        v_pred += interval_buffer[t] * (interval_buffer[t]/number_of_packets_in_a_interval);
                }
                for(int t=0;t<max_number_of_flows_in_a_interval;t++){
                        // calculate Ratio Metric
                        r_pred = interval_buffer[t] / v_pred;
                        r_size += r_pred>0?1:0;
                        r_sum += r_pred;
                }
                // calcuate mean and sd for Ratio Metric
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
                free(interval_buffer);
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


        nb_ports = rte_eth_dev_count_avail();
        if (nb_ports==0)
                rte_exit(EXIT_FAILURE, "No Ethernet ports\n");

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