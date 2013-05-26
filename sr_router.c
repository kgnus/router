/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/


#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*declare variables*/
#define TABL_SIZE 100
#define OP_CODE_REPLY 0x0002
#define ETHERTYPE_IPv6 0x86DD
#define TTL 64
#define BROADCAST 0xffffffffffff
#define ETHIPICMP 38

#define ICMP_ECHO_REP 0
#define ICMP_ECHO_REQ 8
#define ICMP_CODE_0 0
#define ICMP_DEST_UN 3

#define IPPROTO_HOP 0x00
#define IPPROTO_GGP 0x03
#define IPPROTO_IPV4 0x04
#define IPPROTO_IUDP 0x17

#define PORT_80 80

/*#define eth0 2873355880 171.67.238.104
#define eth1 2873355884 171.67.238.108
#define eth2 2873355886 171.67.238.110*/

/*struct for ARP address binding - map IP to MAC addresses*/
/*make one for each interface?*/
typedef struct ad_table {
	uint32_t ip_ad;
	uint8_t  mac_ad[6];
	time_t in_time;
}  arp_table;

/*arp_table *arp_cache[TABL_SIZE]; *//*an array of arp_table pointers*/
arp_table arp_cache[TABL_SIZE]; /*an array of arp_table pointers*/
int table_size;

/*struct for icmp hdr*/
struct icmp_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cs; /*checksum*/
	uint32_t icmp_rest; /*rest of header*/
};


/*queue -> has packet, and ip address that needs a MAC*/
/*struct for queue*/
struct queuing_struct {
	uint8_t *pkt;
	uint32_t pkt_ip;
	struct queuing_struct *next_pkt;
	struct queuing_struct *prev_pkt;
	unsigned int pkt_len;
	unsigned int arp_reqs; /*number of requests -> max 5*/
};
struct queuing_struct *pkt_queue = 0;
struct queuing_struct *qp_walker = 0;
struct queuing_struct *rmv_qp =0;

/*for first thing in ip head we split into bits... cheating.. XD*/
uint8_t ip_1 = 0;

struct sr_ethernet_hdr ethernet_hdr;
struct sr_arphdr arphdr;
struct ip ip_hdr;
int i = 0;
int j = 0;
//struct sr_if eth0_if;
struct icmp_hdr icmp_hd;
uint8_t  broadcast[6] = {255,255,255,255,255,255};
uint8_t *eth_addr;
struct sr_rt *rt_walker = 0;
struct sr_if eth_if;
struct sr_if *if_walker = 0;
int for_us = 0; /*used for ICMP destined for us check*/

time_t arp_flood_t = 0;

/*used in creation of ethernet header for sending packets*/
uint8_t *packet_reply;
uint8_t *icmp_pkt;


/*declare methods*/
int exist_check(struct sr_instance *sr,uint32_t sip, arp_table *table);
void ether_head(uint16_t eth_type, uint8_t *ether_dest, uint8_t *ether_sourc);
void arp_head(unsigned short a_hrd, unsigned short a_pro, unsigned char a_hln,
        unsigned char a_pln, unsigned short a_op, unsigned char *a_sha,
        uint32_t a_sip, unsigned char *a_tha, uint32_t a_tip);
void ip_head(unsigned int i_hl, unsigned int i_v, uint8_t i_tos, uint16_t i_len, uint16_t i_id, uint16_t i_off,
        uint8_t i_ttl, uint8_t i_p, uint16_t i_sum, struct in_addr i_src, struct in_addr i_dest);
void icmp_head(uint8_t i_type, uint8_t i_code, uint16_t i_cs, uint32_t i_rest);
void get_mac(uint32_t sip, arp_table **table, uint8_t *eth_ad);
uint16_t ip_checksum(unsigned int len_ip_hdr, uint8_t *pkt_hdr);
void send_IP_pkt(struct sr_instance *sr, uint8_t *packet, unsigned int len);
void send_ICMP_msg(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_cs, uint32_t icmp_roh, uint8_t *icmp_pk, uint8_t *pack);
uint16_t icmp_checksum(unsigned int len_ip_hdr, uint8_t *pkt_hdr);
void send_ICMP_echo(struct sr_instance *sr, int len, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_cs, uint32_t icmp_roh);
int router_if(struct sr_instance *sr, uint32_t given_ip);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem

 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
	/* REQUIRES */
	assert(sr);

	/* Add initialization code here! */
	table_size = -1;
	
	arp_flood_t = time(NULL);

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,  //struct defined in header
        uint8_t *packet /* lent */,  //this is just a pointer to the full packet w/ ethernet header
        unsigned int len,
        char *interface /* lent */) {
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);


	/*byte arrays don't need ntohs conversion, ints do*/

	/*look at ethernet frame of packet*/
	memcpy(&ethernet_hdr.ether_dhost, &packet[0], 6);
	memcpy(&ethernet_hdr.ether_shost, &packet[6], 6);
	memcpy(&ethernet_hdr.ether_type, &packet[12], 2);
	ethernet_hdr.ether_type = ntohs(ethernet_hdr.ether_type);

	/*look at ether_type and decide what to do*/
	/*packets looked at: ARP, IP, ICMP (in IP)*/

	/*if ARP packet*/
	if (ethernet_hdr.ether_type == ETHERTYPE_ARP) {
		//printf("\nthis is ARP\n");

		/*put packet data into ARP struct*/
		memcpy(&arphdr.ar_hrd, &packet[14],2);
		memcpy(&arphdr.ar_pro, &packet[16],2);
		memcpy(&arphdr.ar_hln, &packet[18],1);
		memcpy(&arphdr.ar_pln, &packet[19],1);
		memcpy(&arphdr.ar_op, &packet[20],2);
		arphdr.ar_op = ntohs(arphdr.ar_op);
		memcpy(&arphdr.ar_sha, &packet[22],6);
		memcpy(&arphdr.ar_sip, &packet[28],4);
		arphdr.ar_sip = ntohl(arphdr.ar_sip);
		memcpy(&arphdr.ar_tha, &packet[32],6);
		memcpy(&arphdr.ar_tip, &packet[38],4);
		arphdr.ar_tip = ntohl(arphdr.ar_tip);


		/*put ARP info of mapping into table if it isn't there*/
		/*we need for values to timeout*/
		
		
		if (exist_check(sr, arphdr.ar_sip, arp_cache) == 0) {

			if (table_size > 98) { /*at max size, just hack a number*/
				table_size = 1;
			} else {
				table_size++;
			}

			arp_cache[table_size].ip_ad = arphdr.ar_sip;
			memcpy(&arp_cache[table_size].mac_ad[0], &arphdr.ar_sha[0],6);
			arp_cache[table_size].in_time = time(NULL);


			//printf("We didn't have, so we added. ARP\n");
		} else { /*it's in the table already, update time*/
			for (i=0; i<=table_size; i++) {
				if (arp_cache[i].ip_ad == arphdr.ar_sip) {
					arp_cache[i].in_time = time(NULL);
				}
			}
		}

		/*ARP request -> packet is asking for a MAC address*/
		/*if dest address is a  Broadcast - ffffffffffff, reply with own info*/
		/*TODO - not just for eth0...*/
		if (arphdr.ar_op == ARP_REQUEST) {
			//printf("this is an ARP request\n");
			if (router_if(sr, arphdr.ar_tip) == 1) { /*if it's destined for me*/
				//printf("they want my  mac\n");
				/* send arp reply*/
				packet_reply = (uint8_t *)malloc(42);

				/*consult eth function for MAC*/
				/*src MAC address not match interface*/
				eth_if = *sr_get_interface(sr, interface); //returns struct sr_if* (in sr_if)

				/*ether hdr*/
				ether_head(htons(ethernet_hdr.ether_type), arphdr.ar_sha, eth_if.addr);

				/*arp hdr*/
					arp_head(arphdr.ar_hrd, arphdr.ar_pro, arphdr.ar_hln,
				        arphdr.ar_pln, htons(OP_CODE_REPLY), eth_if.addr,
				        arphdr.ar_tip, arphdr.ar_sha, arphdr.ar_sip);


				/*send packet*/
				if (sr_send_packet(sr, packet_reply, 42, interface) == -1) {
					fprintf(stderr, "Error sending packet with arp. \n");
				}
				

			} else {
				/*there was a broadcast that wasn't for us, so we drop it*/
			}
		}

		else if (arphdr.ar_op == ARP_REPLY) {
		
			qp_walker = pkt_queue;
			while (qp_walker != 0) {
				if (qp_walker->pkt_ip == arphdr.ar_tip) {
					send_IP_pkt(sr, qp_walker->pkt, qp_walker->pkt_len);
					/*remove packet from queue*/
					/*find element previous to this one*/


					/*if previous node is not null and next node is not null*/
					if (qp_walker->next_pkt != 0 && qp_walker->prev_pkt != 0) {
						
						rmv_qp = qp_walker->prev_pkt;
						qp_walker->prev_pkt->next_pkt = qp_walker->next_pkt;
						qp_walker->next_pkt->prev_pkt = rmv_qp;

					}
					/*if next node is null AND previous node isn't*/
					else if (qp_walker->next_pkt == 0 && qp_walker->prev_pkt != 0) {
						//printf("here2\n");
						qp_walker->prev_pkt->next_pkt = 0;


					} else { /*if prev node is null and the next might or might not be*/
						/*if this is the only node*/
						//printf("here3\n");
						if (qp_walker->next_pkt == 0) {
							pkt_queue = 0;
						} else {
							qp_walker->next_pkt->prev_pkt = 0;
						}


					}

					//printf("We got an arp for this queued packet!!\n");
				}
				qp_walker = qp_walker->next_pkt;
			}
			//printf("we made it out\n");

		}
		/*ARP reply -> we had asked for MAC address resolve, so store it*/

	}



	/**************************************** IP ******************************************/

	/*if IP packet - we forward*/
	/*generate ARP request if we need MAC address for IP address - traffic we route or make*/
	else if (ethernet_hdr.ether_type == ETHERTYPE_IP) {
		//printf(" this is IP\n");


		/*put packet data into IP struct*/
		/* TODO memcpy(&ip_hdr.ip_hl, &packet[14],2);   -> only 4 bits.. so now what?- bit shift*/
		ip_1 = packet[14];
		ip_hdr.ip_hl = packet[14];
		ip_hdr.ip_v = packet[14] << 4; /*bit shift*/
		memcpy(&ip_hdr.ip_tos, &packet[15], 1);
		memcpy(&ip_hdr.ip_len, &packet[16], 2);
		memcpy(&ip_hdr.ip_id, &packet[18], 2);
		memcpy(&ip_hdr.ip_off, &packet[20], 2);
		memcpy(&ip_hdr.ip_ttl, &packet[22], 1);
		memcpy(&ip_hdr.ip_p, &packet[23], 1);
		memcpy(&ip_hdr.ip_sum, &packet[24], 2);
		/*this one is a struct, in_addr, with only one field, unsigned long s_addr (4 bytes)*/
		memcpy(&ip_hdr.ip_src.s_addr, &packet[26], 4);
		ip_hdr.ip_src.s_addr = ntohl(ip_hdr.ip_src.s_addr);
		memcpy(&ip_hdr.ip_dst.s_addr, &packet[30], 4);
		ip_hdr.ip_dst.s_addr = ntohl(ip_hdr.ip_dst.s_addr);

		/*for ICMP*/
		icmp_pkt = (uint8_t *) malloc(28);
		memcpy(&icmp_pkt[0], &packet[14], 28);


		/*is the message for us?*/
		if (router_if(sr, ip_hdr.ip_dst.s_addr) == 1) { /*then message is for us*/


			/*handle ICMP stuff - TTL  -> in hdr, index 22*/
			if (ip_hdr.ip_ttl == 0) {
				/*generate ICMP msg for timeout*/
				send_ICMP_msg(sr, 11, 0, 0, 0, icmp_pkt, packet);
			} else {/*TTL isn't 0*/

				if (ip_hdr.ip_p == IPPROTO_TCP || ip_hdr.ip_p == IPPROTO_UDP) {
					/*if msg is TCP/UDP we shouldn't recieve these, send ICMP back*/
					//printf("TCP/UDP destined for our own itnerface\n");
					/*generate ICMP msg*/
					icmp_pkt = (uint8_t *)malloc(28);
					memcpy(&icmp_pkt[0], &packet[14], 28);
					send_ICMP_msg(sr, 3, 3, 0, 0, icmp_pkt, packet);
				} else if (ip_hdr.ip_p == IPPROTO_ICMP) {
					/*put packet data into ICMP header*/
					memcpy(&icmp_hd.icmp_type, &packet[34], 1);
					memcpy(&icmp_hd.icmp_code, &packet[35], 1);
					memcpy(&icmp_hd.icmp_cs, &packet[36], 2);
					memcpy(&icmp_hd.icmp_rest, &packet[38], 4);

					//printf("icmp type: %d\n", icmp_hd.icmp_type);

					/*check what type of ICMP this is*/
					if (icmp_hd.icmp_type == ICMP_ECHO_REP) {
						//printf("we have an echo reply\n");

					} else if (icmp_hd.icmp_type == ICMP_ECHO_REQ) {
						/*we must respond to echo request with echo reply containing exact data recieved in request*/
						//printf("we have an echo request\n");
						send_ICMP_echo(sr,len, packet, ICMP_ECHO_REP, ICMP_CODE_0, icmp_hd.icmp_cs, icmp_hd.icmp_rest);

					} else if (icmp_hd.icmp_type == ICMP_DEST_UN) {
						//printf("dest unreachable - code:%d\n", icmp_hd.icmp_code);
					}
				}/*else if for ICMP*/
			}/*end if time is more than 0*/
		} /*end if = message is for us*/
		else { /*message is not for us*/
			/*handle ICMP stuff - TTL  -> in hdr, index 22*/
			if (ip_hdr.ip_ttl <= 1) {
				send_ICMP_msg(sr, 11, 0, 0, 0, icmp_pkt, packet);
			} else { /*not time out*/				
				
				if (exist_check(sr, ip_hdr.ip_dst.s_addr, arp_cache) == 1) { /*if we already have MAC address*/

					//printf("we have MAC ad already\n");
					/*we went to route this packet out to the internet, or into an application*/

					send_IP_pkt(sr, packet, len);

					//printf("we forwarded packet!!!\n");

				} else { /* we don't have a MAC address for the IP address*/
					/*so we need to broadcast a request for one*/

					/*Queuing packet:*/


					if (pkt_queue == 0) { //There is nothing in the queue
						pkt_queue = (struct queuing_struct *)malloc(sizeof(struct queuing_struct));
						/*initialize it...*/
						pkt_queue->pkt = (uint8_t *)malloc(len);
						memcpy(&pkt_queue->pkt[0], &packet[0], len);
						pkt_queue->pkt_len = len;
						pkt_queue->pkt_ip = ip_hdr.ip_dst.s_addr;
						pkt_queue->next_pkt = 0;
						pkt_queue->prev_pkt = 0;
						pkt_queue->arp_reqs = 1;
					} else {
						qp_walker = pkt_queue;
						
						while (qp_walker->next_pkt != 0) {
							qp_walker = qp_walker->next_pkt;
						}
						/*save this element to refer to later*/

	
						rmv_qp = qp_walker;

						qp_walker->next_pkt = (struct queuing_struct *)malloc(sizeof(struct queuing_struct));
						qp_walker = qp_walker->next_pkt;

						qp_walker->pkt = (uint8_t *)malloc(len);
						memcpy(&qp_walker->pkt[0], &packet[0], len);
						qp_walker->pkt_len = len;
						qp_walker->pkt_ip = ip_hdr.ip_dst.s_addr;
						qp_walker->next_pkt = 0;
						qp_walker->arp_reqs = 1;
		
						qp_walker->prev_pkt = rmv_qp;
		

					}

					
				}/*don't have MAC addr*/
			}/*not timed out if*/
		} /*if message is not for us end */

	} /* if packet is IPend*/


	/*IPv6 packet - just in case */\
	else if (ethernet_hdr.ether_type == ETHERTYPE_IPv6) {
		/*shouldn't ever get here in this assignment*/
	}




	/*wait a second to check to send ARP reqs*/
	if (time(NULL) - arp_flood_t > 1){

	qp_walker = pkt_queue;
	fflush(stdout);
	/*check for sending aRP requests!!  if not 5, send ARP request, if 5 send host unreachable*/
	while (qp_walker != 0) {
		fflush(stdout);
		if (qp_walker->arp_reqs < 5) {
			/*send ARP REQ*/
			fflush(stdout);
			packet_reply = (uint8_t *)malloc(42);
			/*send ARP pkt- out through each interface of router*/
			if_walker = sr->if_list;
			while (if_walker != 0) {
				/*ether hdr*/
				ether_head(htons(ETHERTYPE_ARP), broadcast, if_walker->addr);
				/*arp hdr*/
	
				
				arp_head(htons(0x0001), htons(0x0800), 0x06, 0x04, htons(ARP_REQUEST), if_walker->addr,
				        htonl(if_walker->ip), broadcast, qp_walker->pkt_ip);
				if (sr_send_packet(sr, packet_reply, 42, if_walker->name) == -1) {
					fprintf(stderr, "Error sending packet with arp. \n\n\n");
				}
								//free(packet_reply);
				if_walker = if_walker->next;
			}
			
			

			qp_walker->arp_reqs++;
		} else { /*arp_reqs is 5, send 5 ARPS*/
			/*send host unreachable and remove from queue*/
			icmp_pkt = (uint8_t *)malloc(28);
			memcpy(&icmp_pkt[0], &qp_walker->pkt[14], 28);
			send_ICMP_msg(sr, 3, 1, 0, 0, icmp_pkt, qp_walker->pkt);

			/*remove it*/
			/*if previous node is not null and next node is not null*/
			if (qp_walker->next_pkt != 0 && qp_walker->prev_pkt != 0) {
				rmv_qp = qp_walker->prev_pkt;
				qp_walker->prev_pkt->next_pkt = qp_walker->next_pkt;
				qp_walker->next_pkt->prev_pkt = rmv_qp;

			}
			/*if next node is null AND previous node isn't*/
			else if (qp_walker->next_pkt == 0 && qp_walker->prev_pkt != 0) {
				qp_walker->prev_pkt->next_pkt = 0;


			} else { /*if prev node is null and the next might or might not be*/
				/*if this is the only node*/
				if (qp_walker->next_pkt == 0) {
					pkt_queue = 0;
				} else {
					qp_walker->next_pkt->prev_pkt = 0;
				}

			}
		}
		qp_walker = qp_walker->next_pkt;
	} /*End qp_walker*/
	arp_flood_t = time(NULL);
}/*has it been more than 1 second?*/
	

	/*check packets in queue for time outs*/
	if (table_size > -1) {
		fflush(stdout);
		for (i=0; i<=table_size; i++) {
			if ((time(NULL) - arp_cache[i].in_time) > 15) {

				/*table_size is the very last element*/
				memcpy(&arp_cache[i].ip_ad, &arp_cache[table_size].ip_ad,4);
				memcpy(&arp_cache[i].mac_ad, &arp_cache[table_size].mac_ad, 6);
				arp_cache[i].in_time = arp_cache[table_size].in_time;
				table_size--;
			}
		}
	}/*end check packets for queue time outs*/

}/* end sr_ForwardPacket */









/*---------------------------------------------------------------------
* Method: is this IP one of the router's interfaces?
*
*---------------------------------------------------------------------*/
int router_if(struct sr_instance *sr, uint32_t given_ip) {

	/*check if the given ip matches a router interface*/
	if_walker = sr->if_list;
	while (if_walker != 0) {
		//	printf("in router+if *%s\n", if_walker->name);
		if (ntohl(given_ip)  ==  if_walker->ip) {
			return 1;
		}
		if_walker = if_walker->next;
	}
	return 0;


}

/*---------------------------------------------------------------------
* Method: ICMP msg generation for echo
*
*---------------------------------------------------------------------*/
void send_ICMP_echo(struct sr_instance *sr, int len, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_cs, uint32_t icmp_roh) {
	/*need to generate ICMP msgs for (on all interfaces of router):
	ICMP Echo reply */

	

	/*for checksum*/
	uint8_t ip_hdr_cs[20];
	int size_of_ICMP = len-14-20;
	uint8_t icmp_hdr_cs[size_of_ICMP];

	/*ethernet hdr + IP hdr + ICMP hdr  = 38  + 28 = 66*/
	/*28 is for previous IP header, plus 64 bits of data*/
	packet_reply = (uint8_t *)malloc(len);

	/*need exact data as was in original packet*/
	memcpy(&packet_reply[0], &packet[0], len);


	rt_walker = sr->routing_table;
	while ((rt_walker != 0) && (ntohl(rt_walker->dest.s_addr) != ip_hdr.ip_src.s_addr)) {
		//printf("*in icmp echo%s\n", rt_walker->interface);
		rt_walker = rt_walker->next;
	}
	if (rt_walker == 0) {
		rt_walker = sr->routing_table; /*make it eth0 if it doesn't match other stuff*/
	}


	/*consult eth function for MAC*/
	/*src MAC address not match interface*/
	eth_if = *sr_get_interface(sr, rt_walker->interface); //returns struct sr_if* (in sr_if)

	/*ether hdr*/
	ether_head(htons(ETHERTYPE_IP), ethernet_hdr.ether_shost, eth_if.addr);

	ip_hdr.ip_dst.s_addr = htonl(ip_hdr.ip_dst.s_addr);
	ip_hdr.ip_src.s_addr = htonl(ip_hdr.ip_src.s_addr);
	memcpy(&packet_reply[26], &ip_hdr.ip_dst.s_addr, 4);
	memcpy(&packet_reply[30], &ip_hdr.ip_src.s_addr, 4);

	/*change checksum in packet which is at 24,25*/
	/*calculate new checksum*/
	/*put ip header into ip_hdr_cs*/
	memcpy(&ip_hdr_cs[0], &packet_reply[14], 20);
	ip_hdr.ip_sum = htons(ip_checksum(20, ip_hdr_cs));
	memcpy(&packet_reply[24], &ip_hdr.ip_sum, 2);

	/*generate checksum, and what is rest of header???*/
	/*ICMP hdr*/
	/*NEED ALL OF DATA FOR ICMP CHECKSUM it seems.. */
	memcpy(&icmp_hdr_cs[0],  &packet[34], size_of_ICMP);
	memcpy(&icmp_hdr_cs[0], &icmp_type, 1);
	memcpy(&icmp_hdr_cs[1], &icmp_code, 1);


	/*change checksum in packet which is at 24,25*/
	/*calculate new checksum*/
	/*put ip header into ip_hdr_cs*/
	icmp_cs = htons(icmp_checksum(size_of_ICMP, icmp_hdr_cs));

	memcpy(&packet_reply[34], &icmp_hdr_cs[0], 12);
	memcpy(&packet_reply[36], &icmp_cs, 2);
	//memcpy(&packet_reply[38], &icmp_pk, 28);


	/*send packet*/
	if (sr_send_packet(sr, packet_reply, len, eth_if.name) == -1) {
		fprintf(stderr, "Error sending packet with arp. \n");
	}
	
	
}


/*---------------------------------------------------------------------
 * Method: ICMP msg generation
 * for port unreachable and Timeout
 *---------------------------------------------------------------------*/
void send_ICMP_msg(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_cs, uint32_t icmp_roh, uint8_t *icmp_pk, uint8_t *pack) {
	/*need to generate ICMP msgs for (on all interfaces of router):
	host unreachable || port unreachable || time out -> TTL is 0 or 1 || ICMP Echo reply */

	unsigned int found = 0;

	/*for checksum*/
	int size_of_packet = 70;
	uint8_t ip_hdr_cs[20];
	int size_of_ICMP = size_of_packet-14-20;


	uint8_t icmp_hdr_cs[size_of_ICMP];
	
	
	uint8_t d_eth[6]; /*dest in this reply packet*/
	uint8_t s_eth[6];
	memcpy(&d_eth[0], &pack[6], 6);
	memcpy(&s_eth[0], &pack[0], 6);
	struct in_addr d_ip;
	struct in_addr s_ip;


	/*ethernet hdr + IP hdr + ICMP hdr  = 42  + 28 = 70*/
	/*28 is for previous IP header, plus 64 bits of data*/
	packet_reply = (uint8_t *)malloc(size_of_packet);

	/*ether hdr */
	ether_head(htons(ETHERTYPE_IP), d_eth, s_eth);


	/*get eth# for MAC from interface*/
	if_walker = sr->if_list;

	while (if_walker != 0 && found != 6) {
		for (i=0; i<6; i++) {
			if (s_eth[i] == if_walker->addr[i]) {
				found++;
			}
		}
		if (found < 6) {
			if_walker = if_walker->next;
			found = 0;
		}
	}
	
	/*dest is dest in packet*/
	memcpy(&d_ip.s_addr, &pack[26], 4);
	d_ip.s_addr = htonl(d_ip.s_addr );
	/*if it's a host unreachable use packet's IP*/
	if ( icmp_type == 3 && icmp_code == 1){
		memcpy(&s_ip.s_addr, &pack[30], 4);
		s_ip.s_addr = htonl(s_ip.s_addr);
	} else { /*if it's Timeout or port unreachable from me, use interfaces IP*/
		memcpy(&s_ip.s_addr, &if_walker->ip, 4);
		s_ip.s_addr = htonl(s_ip.s_addr);
	}

	ip_head(ip_hdr.ip_hl, ip_hdr.ip_v , ip_hdr.ip_tos, size_of_packet - 14, 0, 0,
	        TTL, 1, ip_hdr.ip_sum, s_ip, d_ip);

	/*change checksum in packet which is at 24,25*/
	/*calculate new checksum*/
	/*put ip header into ip_hdr_cs*/
	memcpy(&ip_hdr_cs[0], &packet_reply[14], 20);
	ip_hdr.ip_sum = htons(ip_checksum(20, ip_hdr_cs));
	memcpy(&packet_reply[24], &ip_hdr.ip_sum, 2);

	/*generate checksum, and what is rest of header???*/
	/*ICMP hdr*/
	icmp_head(icmp_type, icmp_code, icmp_cs, htonl(icmp_roh));

	/*change checksum in packet which is at 24,25*/
	/*calculate new checksum*/
	/*put ip header into ip_hdr_cs*/

	/*put in data of previous packet*/
	memcpy(&packet_reply[42], &icmp_pk[0], 28);

	/*data for checksum*/
	memcpy(&icmp_hdr_cs[0], &packet_reply[34], size_of_ICMP);
	icmp_cs = htons(icmp_checksum(size_of_ICMP, icmp_hdr_cs));
	memcpy(&packet_reply[36], &icmp_cs, 2);

	/*send packet*/
	if (sr_send_packet(sr, packet_reply, size_of_packet, if_walker->name) == -1) {
		fprintf(stderr, "Error sending packet with arp. \n");
	}


}


/*---------------------------------------------------------------------
 * Method: send IP pkt
 *
 *---------------------------------------------------------------------*/

void send_IP_pkt(struct sr_instance *sr, uint8_t *pack, unsigned int len) {

	/*for checksum*/
	uint8_t ip_hdr_cs[20];

	/*we need to change the MAC header*/
	packet_reply = (uint8_t *)malloc(len);

	memcpy(&packet_reply[0], &pack[0], len); /*copy over entire packet*/


	/*consult rtable to get eth#*/
	rt_walker = sr->routing_table;
	/*in sr_rt, next = 0 for last element!*/
	while ((rt_walker != 0) && (ntohl(rt_walker->dest.s_addr)!= ip_hdr.ip_dst.s_addr)) {

		rt_walker = rt_walker->next;
	}
	if (rt_walker == 0) {
		rt_walker = sr->routing_table; /*make it eth0 if it doesn't match other stuff*/
	}

	/*consult eth function for MAC*/
	/*src MAC address not match interface*/
	eth_if = *sr_get_interface(sr, rt_walker->interface); //returns struct sr_if* (in sr_if)

	memcpy(&packet_reply[6], &eth_if.addr[0], 6);

	/*get eth*/
	for (j=0; j<=table_size; j++) {
		if (arp_cache[j].ip_ad == ntohl(rt_walker->gw.s_addr)) {

			memcpy(&packet_reply[0], &arp_cache[j].mac_ad[0], 6);/*error - int from ptr wtihout cast */
		

		}
	}


	/*decrement TTL  @ i=22 in packet*/
	ip_hdr.ip_ttl--;
	memcpy(&packet_reply[22], &ip_hdr.ip_ttl, 1);

	/*change checksum in packet which is at 24,25  FOR IP*/
	/*calculate new checksum*/
	/*put ip header into ip_hdr_cs*/
	memcpy(&ip_hdr_cs[0], &packet_reply[14], 20);
	ip_hdr.ip_sum = ntohs(ip_checksum(20, ip_hdr_cs));
	memcpy(&packet_reply[24], &ip_hdr.ip_sum, 2);



	/*send packet*/

	//printf("sending IP packet\n");
	if (sr_send_packet(sr, packet_reply, len, rt_walker->interface) == -1) {
		fprintf(stderr, "Error forwarding ip packet. \n");
	}
	
}



/*---------------------------------------------------------------------
 * Method: checksum
 *
 *---------------------------------------------------------------------*/

uint16_t ip_checksum(unsigned int len_ip_hdr, uint8_t *pkt_hdr) {
	/* set old checksum to zero, which is at 24 and 25 - but in only ip header at 11 and 12*/
	pkt_hdr[10] = 0;
	pkt_hdr[11] = 0;

	uint16_t bytes_2;
	uint32_t sum = 0;
	uint16_t i;
	uint16_t convert1;
	uint16_t convert2;

	for (i=0; i<len_ip_hdr; i=i+2) {
		convert1 = (uint16_t)pkt_hdr[i];
		convert2 = (uint16_t)pkt_hdr[i+1];
		bytes_2 = ((convert1<<8)&0xFF00)+(convert2&0xFF);
		sum = sum + (uint32_t) bytes_2;
	}

	while (sum>>16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;

	return ((uint16_t) sum);

}

/*---------------------------------------------------------------------
 * Method: checksum for imcp
 *
 *---------------------------------------------------------------------*/

uint16_t icmp_checksum(unsigned int len_icmp_hdr, uint8_t *pkt_hdr) {
	/* set old checksum to zero,*/
	pkt_hdr[2] = 0;
	pkt_hdr[3] = 0;

	uint16_t bytes_2;
	uint32_t sum = 0;
	uint16_t i;
	uint16_t convert1;
	uint16_t convert2;

	for (i=0; i<len_icmp_hdr; i=i+2) {
		convert1 = (uint16_t)pkt_hdr[i];
		convert2 = (uint16_t)pkt_hdr[i+1];
		bytes_2 = ((convert1<<8)&0xFF00)+(convert2&0xFF);
		sum = sum + (uint32_t) bytes_2;
	}

	while (sum>>16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;

	return ((uint16_t) sum);

}



/*---------------------------------------------------------------------
 * Method:int exist_check(uint32_t sip, arp_table **table)
 *returns 1 if it is in there, 0 if not
 *---------------------------------------------------------------------*/

int exist_check(struct sr_instance *sr, uint32_t sip, arp_table *table) {

	if (table_size < 0) {
		return 0;
	}


	rt_walker = sr->routing_table;
	/*in sr_rt, next = 0 for last element!*/
	//printf("..+++++++++.%u... %u\n", ntohl(rt_walker->dest.s_addr), sip);
	while ((rt_walker != 0) && (ntohl(rt_walker->dest.s_addr)!= sip)) {

		rt_walker = rt_walker->next;
	}
	if (rt_walker == 0) {
		rt_walker = sr->routing_table; /*make it eth0 if it doesn't match other stuff*/
	}
	/*consult eth function for MAC*/
	/*src MAC address not match interface*/
	eth_if = *sr_get_interface(sr, rt_walker->interface); //returns struct sr_if* (in sr_if)

	/*get eth*/
	for (j=0; j<=table_size; j++) {
		//printf("..%u  walker: %u\n", arp_cache[j].ip_ad , ntohl(rt_walker->gw.s_addr));
		if (arp_cache[j].ip_ad == ntohl(rt_walker->gw.s_addr)) {
			//printf("we have the address\n");
			return 1;

		}
	}
	return 0;
}




/*---------------------------------------------------------------------
 * Method: uint8_t *ether_head(uint16_t eth_type, uint8_t *ether_dest, uint8_t *ether_sourc)
create ether header
 *  input data should be 14 bytes in length
 *---------------------------------------------------------------------*/
void ether_head(uint16_t eth_type, uint8_t *ether_dest, uint8_t *ether_sourc) {
	memcpy(&packet_reply[0], &ether_dest[0], 6);
	memcpy(&packet_reply[6], &ether_sourc[0], 6);
	memcpy(&packet_reply[12], &eth_type, 2);
}


/*---------------------------------------------------------------------
 * Method: create arp header
 *
 *---------------------------------------------------------------------*/
void arp_head(unsigned short a_hrd, unsigned short a_pro, unsigned char a_hln,
        unsigned char a_pln, unsigned short a_op, unsigned char *a_sha,
        uint32_t a_sip, unsigned char *a_tha, uint32_t a_tip) {
	memcpy(&packet_reply[14], &a_hrd, 2);
	memcpy(&packet_reply[16], &a_pro, 2);
	memcpy(&packet_reply[18], &a_hln, 1);
	memcpy(&packet_reply[19], &a_pln, 1);
	memcpy(&packet_reply[20], &a_op, 2);

	memcpy(&packet_reply[22], &a_sha[0], 6);
	a_sip = htonl(a_sip);
	memcpy(&packet_reply[28], &a_sip, 4);
	memcpy(&packet_reply[32], &a_tha[0], 6);
	a_tip = htonl(a_tip);
	memcpy(&packet_reply[38], &a_tip, 4);
}

/*---------------------------------------------------------------------
 * Method: create  IP header
 *
 *---------------------------------------------------------------------*/
void ip_head(unsigned int i_hl, unsigned int i_v, uint8_t i_tos, uint16_t i_len, uint16_t i_id, uint16_t i_off,
        uint8_t i_ttl, uint8_t i_p, uint16_t i_sum, struct in_addr i_src, struct in_addr i_dest) {


	memcpy(&packet_reply[14], &ip_1, 1);
	memcpy(&packet_reply[15], &i_tos, 1);
	i_len = htons(i_len);
	memcpy(&packet_reply[16], &i_len, 2);
	memcpy(&packet_reply[18], &i_id, 2);
	memcpy(&packet_reply[20], &i_off, 2);
	memcpy(&packet_reply[22], &i_ttl, 1);
	memcpy(&packet_reply[23], &i_p, 1);
	memcpy(&packet_reply[24], &i_sum, 2);
	i_src.s_addr = htonl(i_src.s_addr);
	memcpy(&packet_reply[26], &i_src.s_addr, 4);
	i_dest.s_addr = htonl(i_dest.s_addr);
	memcpy(&packet_reply[30], &i_dest.s_addr, 4);


}

/*---------------------------------------------------------------------
 * Method: create  ICMP header
 *
 *---------------------------------------------------------------------*/
void icmp_head(uint8_t i_type, uint8_t i_code, uint16_t i_cs, uint32_t i_rest) {
	memcpy(&packet_reply[34], &i_type, 1);
	memcpy(&packet_reply[35], &i_code, 1);
	memcpy(&packet_reply[36], &i_cs, 2);
	memcpy(&packet_reply[38], &i_rest, 4);
}
