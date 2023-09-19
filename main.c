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
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>


#define RTE_LOGTYPE_DDD RTE_LOGTYPE_USER1


#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
// #define TX_RING_SIZE 1024

#define MBUF_CACHE_SIZE 256
#define MAX_PKT_BURST 32 // number of packets to recevie / transfer in a burs

static volatile bool force_quit;

static int promiscuous_on = 1;


static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        },
};

struct rte_mempool *mbuf_pool = NULL;


#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
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


static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = 1;
        // const uint16_t tx_rings = 1;
        // uint16_t nb_txd = TX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;
        // struct rte_eth_txconf txconf;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;

        rte_eth_dev_info_get(port, &dev_info);
        //if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        //        port_conf.txmode.offloads |=
        //                DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        /* Configure the Ethernet device. */
        // change zero to tx_ring if you want
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
        /*
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        // Allocate and set up 1 TX queue per Ethernet port.
        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                rte_eth_dev_socket_id(port), &txconf);
                if (retval < 0)
                        return retval;
        }
        */
        
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


        printf("Port %u: \n\n",
			port);

	/* initialize port stats */
	memset(&port_statistics, 0, sizeof(port_statistics));



        return 0;
}







/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and exports flows.
 */
static int lcore_main(__rte_unused void *dummy){

        
        struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
        struct rte_mbuf *m;
        unsigned i,j, port, lcore_id, nb_rx;
       	struct lcore_queue_conf *qconf;


        /* It is a performance measurement
         * Check that the port is on the same NUMA node as the polling thread
         * for best performance.
         */
        RTE_ETH_FOREACH_DEV(port)
                if (rte_eth_dev_socket_id(port) > 0 &&
                                rte_eth_dev_socket_id(port) !=
                                                (int)rte_socket_id())
                        printf("WARNING, port %u is on remote NUMA node to "
                                        "polling thread.\n\tPerformance will "
                                        "not be optimal.\n", port);

       	lcore_id = rte_lcore_id();
        qconf = &lcore_queue_conf[lcore_id];


        if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, DDD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, DDD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		port = qconf->rx_port_list[i];
		RTE_LOG(INFO, DDD, " -- lcoreid=%u portid=%u\n", lcore_id,
			port);

	}

        while(!force_quit){
                for (i = 0; i < qconf->n_rx_port; i++) {

			port = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST);

			if (unlikely(nb_rx == 0))
				continue;

			port_statistics[port].rx += nb_rx;


                        // processing packets
			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));  // prefetches a cache line into all layer of caches
			}
		}
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

        // lcore_id = rte_lcore_id();
        
        /* Initialize the Environment Abstraction Layer (EAL). */
        int ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");


        argc -= ret;
        argv += ret;

        force_quit = false;
        signal(SIGINT, signal_handler);
        signal(SIGINT, signal_handler);


        // to-do: there is no essential need to have more than one port. There is two options:
          // 1: incoming packets from source captured by our DDD and then they will be forwarded to Suricata. Also after proceesing packets, we will generate rule file and send for Suricata. 
          // 2: Incoming packets from source will go for Suricata and also will be mirroed for our DDD. An we just need to generate and send rule file to Surica. (Here I use this method)
        /* Check that there is an even number of ports to send/receive on. */
        
        
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

        /* Creates a new mbuf mempool in memory to hold the mbufs objects ( that store packets).
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