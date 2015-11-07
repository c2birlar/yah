
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


/*
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
*/

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */ 

  //Figure out which type and code should be put in ICMP header
  int icmp_type_code = -1;
  int drop_packet = 0;
  
  sr_ethernet_hdr* ethernet_hdr = packet;
  uint16_t ethype = ethertype(packet);//either ARP or IP
  int minLenIP = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
  int minLenARP = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  
  if (ethtype == ethertype_ip){
    //IP Packet
    int normal_ip_forward = 0;
    int icmp_send = 0;

    sr_ip_hr_t* ip_header  = packet + sizeof(struct sr_ethernet_hdr);
    
    //1.Basic Standards: Make  sure it meets min length of packet
    //then check checksum correct; set drop_packet if necessary
    if (len < minLenIP){
      fprintf(stderr, "Failed to access IP header, too small\n");
      drop_packet = 1;
      //return;
    }
    uint16_t initCksum = cksum(ip_header, sizeof(struct sr_ip_hdr));
    if (ntohl(ip_header->ip_sum) != initCksum){
      drop_packet = 1;
      icmp_type_code = -1;
    }

    //2.Figure out if either drop packet, or ICMP neccessary, 
    //or just IP forward
    if (drop_packet == 0){
       uint32_t dest_ip = ntohl(ip_header->ip_dst);
       if (destinedToRouter(dest_ip)){
	 //destined for us
	 icmp_type_code = icmp(sr,packet);
	 if (icmp_type_code == -1){
	   //unknown
	   drop_packet = 1;
	 }else{
	   icmp_send = 1;
	 }
       }else{//not destined to us
	 icmp_type_code = icmp(sr,packet);
	 if (icmp_type_code == -1){
	   normal_ip_forward = 1;//good to forward
	 }else{
	   icmp_send = 1;
	 }
       }
    }
   
    //recompute ttl if going to ip forward
    if (normal_ip_forward == 1){
      //decrment ttl by 1, recompute checksum over modifified header
      ip_header->ip_ttl = htonl(ntohs(ip_header->ip_ttl) - 1);
      uint16_t modCksum = cksum(ip_header, sizeof(struct sr_ip_hdr));
    }
    
    //if not dropping
    if (drop_packet == 0){
      //check arp cache for mac address
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), 
							 htonl(ip_header->ip_dst));

      if (arp_entry != NULL){
	unsigned char dest_mac[sr_IFACE_NAMELEN] = arp_entry->mac;
	//use this to send to next hop ip, free entry
	free(arp_entry);
	
	//ICMP
	if (icmp_send == 1){
	  //send back to source IP
	  //Create Ethernet header, IP header and ICMP header
	  int buff_size = minLenIP + sizeof(struct sr_icmp_t3_hdr) 
	    + ICMP_DATA_SIZE;//plus more????????????
	  uint8_t* buf = malloc(buff_size);
	  setIcmpHeaders(buf, icmp_type_code);
	  sendIcmp(sr,buf, interface, buff_size);

	}else{
	  if (normal_ip_forward == 1){
	    //normal IP forward, no errors detected
	    //change old contents
	    ethernet_hdr->dhost = dest_mac;
	    struct sr_if* ifRecord = getIfRecord(sr, dest_ip);
	    ethernet_hdr->shost = ifRecord->addr;
	    ip_header->ip_sum = modCksum;
	    //Send packet
	    int ret = sr_send_packet(sr, packet, len, interface);
	    if (ret != 0){
	      perror("packet not sent");
	      exit(1);
	    }
	  }
	}
      }else{
	//entry not found ARP cache
	req = arpcache_queuereq(htonl(dest_ip),packet,len);
	//rest done by arp_cahce. functions
	//ARP reply process code handles this
      }
    }//else ignore packets (drop packet)
    
  }else if (ethtype == ethertype_arp){/*ARP*/
    if (len < minLengthARP){
      fprintf(stderr, "Failed to access ARP header, too small\n");
      drop = 1;
      //return;
    }
    if (drop == 0){
      if (destinedToRouter(dest_ip)){
	sr_ethernet_hdr_t* ethernet_hdr = packet;
	sr_arp_hdr_t* arp_header = packet + sizeof(struct sr_ethernet_hdr);
	if (ntohl(arp_header->opcode) == arp_op_reply){
	  //process reply
	  //move entries from ARP request queue to ARP cache
	  struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha,
						    ntohl(arp_header->ar_sip));
	  if (req){
	     struct sr_packet* traverser = request->packets;
	     while(traverser != NULL){
	       //normal IP forward, no errors detected
	       //change old contents
	       struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), 
								  dest_ip);
	       sr_ip_hdr_t* ip_header = packet + sizeof(struct sr_ethernet_hdr);
	       sr_ethernet_hdr_t* out_eth = packet;
	       out_eth->dhost = arp_entry->mac;
	       
	       struct sr_if* ifRecord = getIfRecord(sr, dest_ip);
	       out_eth->shost = ifRecord->addr;
	       uint16_t modCksum = cksum(ip_header, sizeof(struct sr_ip_hdr));
	       ip_header->ip_sum = htonl(modCksum);
	       //Send packet
	       int ret = sr_send_packet(sr, packet, len, interface);
	       if (ret != 0){
		 perror("packet not sent");
		 exit(1);
	       }
	  
	       traverser = packets->next;
	     }
      
	     sr_arpreq_destroy(&(sr->cache), req);
	  }
	}else{
	  //process request and send reply
	  //swap MAC addresses
	  sr_ethernet_hdr_t* out_eth = ethernet_hdr;
	  sendInReverse(out_eth, ethernet_hdr);
	  
	  //process request, send ARP reply
	  arp_header->opcode = htonl(arp_op_reply);
	  arp_header->ar_tip = arp_header->ar_sip;
	  struct sr_if* ifRecord = getIfRecord(sr, dest_ip);
	  arp_header->ar_sip = htonl(ifRecord->ip);
	  arp_header->arp_tha = arp_header->sha;
	  arp_header->sha = ifRecord->addr;
	  //Send packet
	  int ret = sr_send_packet(sr, packet, len, ifRecord->name);
	  if (ret != 0){
	    perror("packet not sent");
	    exit(1);
	  }
	}
      }else{
	break;
	//forward packet
      }
    } 
  }else{
    fprintf(stderr, "Unrecognized Ethernet Type, while processing\n");
  }
}/* end sr_ForwardPacket */



/*************************************************************************************/
/*                         Helper Functions   */


/*sends packet, checks any errors and frees buffer
 */
void sendPacket(struct sr_instance* sr, uint8_t* buf, char* iface, int len){
  //send out icmp packet now
  //Send packet
  int ret = sr_send_packet(sr, buf, len, iface);
  if (ret != 0){
    perror("packet not sent");
    exit(1);
  }
  free(buf);
 
}

/*
 *This function is only called from the arp cache handler, and is done so
 *when five (5) arp requests have been sent without a response
 */
void sendIcmpHostUnreachable(struct sr_instance *sr, uint8_t*buf, char* iface, int len){
  int destHostUnReach = 0x0301ffff;//type 3,code 1
  setIcmpHeaders(buf, destHostUnReach);
  sendPacket(sr,buf,iface, len);
}


/*Returns ICMP type and code in 1 integer
 * If -1, then no need for ICMP protocol
 */
int icmp(struct sr_instance* sr, uint8_t* packet){
  sr_ip_hdr_t* ip_header = packet + sizeof(struct sr_ethernet_hdr);
  sr_icmp_hdr_t* icmp_header = ip_header + sizeof(struct sr_ip_hr);
   //Type and code for ICMP condition:
  int echoReply       = 0x00ffffff;//type 0,code ?
  int destNetUnReach  = 0x0300ffff;//type 3,code 0
  int destHostUnReach = 0x0301ffff;//type 3,code 1
  int portUnReach     = 0x33ffffff;//type 3,code 3
  int timeExceed      = 0x0b00ffff;//type 11,code 0

  //Figure out which type and code should be put in ICMP header
  int icmp_type_code = -1;

  uint32_t dest_ip = ntohl(ip_header->ip_dst);
  
  if (destinedToRouter(dest_ip)){
    //destined to us  
    uint8_t protocol = ntohs(ip_header->ip_p);
    
    if (protocol == ip_protocol_icmp){
      if (ntohs(icmp_header->icmp_type) == 8){
	//This is an echo request
	icmp_type_code = echoReply;
	//Send echoReply
      }
    }else if ((protocol == 6) || (protocol == 17)) {
      // must be a tcp/udp packet; 
      icmp_type_code = portUnReach;
    }else{
      icmp_type_code = -1;
    }
  }else{
    //Remember to discard packet ?????????
    if (ntohs(ip->header->ip_ttl) <= 0){
      icmp_type_code = timeExceed;
    }else{
      //Check if IP address in rtable by traversing it.
      char iface[sr_IFACE_NAMELEN] = checkRTable(sr,dest_ip);
      if ((srcmp(iface,"")) == 0){
	//means no route
	icmp_type_code = destNetUnReach;
      }
    }
  }
  return icmp_type_code;
}

bool destinedToRouter(uint32_t d){
   //interfaces IP addresses
 
  struct in_addr addrptr;
  struct in_addr addrptr2;
  struct in_addr addrptr3;
  int retval;
  retval = inet_atom("192.168.2.1", &addrptr);
  retval = inet_atom("172.64.3.1", &addrptr2);
  retval = inet_atom("10.0.1.11", &addrptr3);
  uint32_t if1 = (unsigned long) addrptr.s_addr;
  uint32_t if2 = (unsigned long) addrptr2.s_addr;
  uint32_t if3 = (unsigned long) addrptr3.s_addr;
 
  return  ((d == if1) || (d==if2) ||( d==if3));
}

char* checkRTable(struct sr_instance* sr, uint32_t dest_ip){
  struct sr_rt* rt_walker;
  rt_walker = sr->routing_table;
  if(rt_walker == 0){
    perror("routing table is empty\n");
    exit(1);
  }
  char* iface = "";
  if (rt_walker->dest == dest_ip){
    iface = rt_walker->interface;
  }else{
    while(rt_walker->next){
      rt_walker = rt_walker->next;
      if (rt_walker->dest == dest_ip){
	iface= rt_walker->interface;
      }
    }
  }
  return iface;
}

void sendInReverse(sr_ethernet_hdr_t* out_eth,  sr_ethernet_hdr_t* ethernet_hdr){
  //just swap source's MAC address with ours (this is of the router who sent it to
  //us, not the actual source)
  out_eth->ether_dhost = ethernet_hdr->ether_shost;
  out_eth->ether_shost = ethernet_hdr->ether_dhost;
}

void setIcmpHeaders(uint8_t* buf, int icmp_type_code){
  int minLenIP = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
   //Type and code for ICMP condition:
  int echoReply       = 0x00ffffff;//type 0,code ?
  int destNetUnReach  = 0x0300ffff;//type 3,code 0
  int destHostUnReach = 0x0301ffff;//type 3,code 1
  int portUnReach     = 0x33ffffff;//type 3,code 3
  int timeExceed      = 0x0b00ffff;//type 11,code 0
 
 
  //set ethernet header fields
  sr_ethernet_hdr_t* ethernet_hdr = buf;
  sr_ethernet_hdr_t* out_eth = buf
  out_eth->ether_type = htons(ethertype_ip);
  //swap MAC addresses
  sendInReverse(out_eth, ethernet_hdr);
	  

  //set for IP header fields
  sr_ip_hdr_t* out_ip = buf + sizeof(struct sr_ethernet_hdr);
  out_ip->ip_tos = 0;
  out_ip->ip_len = htonl(ip_header->ip_len);//need to add length of data
  out_ip->ip_id = 0;
  out_ip->ip_off = 0;
  out_ip->ip_ttl = htonl(35);//default
  out_ip->ip_p = htonl(ip_protocol_icmp);
  out_ip->ip_sum = 0;
  //Go back through same interface it came through
  struct sr_if* ifRecord = getIfRecord(sr, dest_ip);
  uint32_t new_src_IP = ifRecord->ip;  
  out_ip->ip_src = htonl(new_src_IP);
  out_ip->dest_ip =  ip_header->ip_src;
  out_ip->ip_sum = cksum(out_ip, sizeof(struct sr_ip_hdr));//should be 16 bit words
	  
  //Set ICMP header
  //st_icmp_hdr_t* out_icmp = buf + minLenIP;
 	  
  //needed for after ICMP header (for the dest)
  uint8_t* copy_buf = malloc(sizeof(sr_ip_hdr) + 8);
  copy_buf = ip_header;
  //set fields
  if ((icmp_type_code == destNetUnReach) || (icmp_type_code == destHostUnReach)
      || (icmp_type_code == portUnReach)){
    sr_icmp_t3_hdr* icmp_t3_hdr = buff + minLenIP;
    icmp_t3_hdr->icmp_type = htons((uint8_t)3);
    if (icmp_type_code == destNetUnReach){
      icmp_t3_hdr->icmp_code = htons((uint8_t)0);
    }else if (icmp_type_code == destHostUnReach){
      icmp_t3_hdr->icmp_code = htons((uint8_t)1);
    }else{//portUnReach
      icmp_t3_hdr->icmp_code = htons((uint8_t)3);
    }
    icmp_t3_hdr->sum = 0;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->mtu = 0;
    icmp_t3_hdr->sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
    //original internet header + first 64 bits of data
    icmp_t3_hdr->data = copy_buf;
    //you'll need to free this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  }else if (icmp_type_code == echoReply){
    //we'll use a t3 header because size is same as echo reply header
    //the unused field is now the id 
    sr_icmp_t3_hdr* icmp_t3_hdr = buff + minLenIP;
    icmp_t3_hdr->icmp_type = htons((uint8_t)0);
    icmp_t3_hdr->icmp_code = htons((uint8_t)0);
    icmp_t3_hdr->sum = 0;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->mtu = 0;
    icmp_t3_hdr->sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
	    
    //data from original packet is put after ICMP header
    icmp_t3_hdr->data= copy_buf;
  }else if (icmp_type_code == timeExceed){
    sr_icmp_hdr* icmp_hdr = buff + minLenIP;
    icmp_hdr->icmp_type = htons((uint8_t)11);
    icmp_hdr->icmp_code = htons((uint8_t)0);
    icmp_hdr->sum = 0;
    icmp_hdr->sum = cksum(icmp_hdr, sizeof(struct sr_icmp_hdr));
    buf + minLenIP + sizeof(struct sr_icmp_hdr)= copy_buf;
  }else{
    break;
  }
}
