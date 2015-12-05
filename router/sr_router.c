
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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*Initializers*/
//Type and code for ICMP condition:
int echoReply       = 0x00ffffff;//type 0,code ?
int destNetUnReach  = 0x0300ffff;//type 3,code 0
int destHostUnReach = 0x0301ffff;//type 3,code 1
int portUnReach     = 0x33ffffff;//type 3,code 3
int timeExceed      = 0x0b00ffff;//type 11,code 0
int eth_size = sizeof(struct sr_ethernet_hdr);


int icmp_type_code = -1;
int drop_packet = 0;
uint32_t dest_ip;
uint16_t modCksum;

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr){
    // REQUIRES 
    assert(sr);

// Initialize cache and cache cleanup thread 
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
} 

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
		     uint8_t* packet, /*lent*/
		     unsigned int len, 
		     char* interface){
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  
  printf("*** -> Received packet of length %d \n",len);

  /*Initializers*/
  //for ICMP
  uint16_t ethtype = ethertype(packet);//either ARP or IP
  
  if (ethtype == ethertype_ip){
    int iRet = handle_IP_packet(sr,packet,len, interface);
    if (iRet != 1){
      fprintf(stderr, "Didn't process IP packet properly\n");
    }
  }else if (ethtype == ethertype_arp){/*ARP*/
    int aRet =  handle_ARP_packet(sr,packet,len, interface);
    if (aRet != 1){
      fprintf(stderr, "Didn't process ARP packet properly\n");
    }
  }else{
    fprintf(stderr, "Unrecognized Ethernet Type, while processing\n");
  }
}/* end sr_handlePacket */



/*******************************Helper Functions******************************/

/*********General Helper Functions ******************/


/*Returns whether IP given is one of router's ip 
 address*/
_Bool destinedToRouter(uint32_t d){
   //interfaces IP addresses
  struct in_addr addrptr, addrptr2, addrptr3;
  int retval, retval2, retval3;

  //dot notation to binary data, store in struct in_addr
  retval = inet_aton("192.168.2.1", &addrptr);
  retval2 = inet_aton("172.64.3.1", &addrptr2);
  retval3 = inet_aton("10.0.1.11", &addrptr3);
  if ((retval == 0) || (retval2 == 0) || (retval3 == 0)){
    fprintf(stderr, "Failed determining IP address in dot notation\n");
  }
  uint32_t if1 = (unsigned long) addrptr.s_addr;
  uint32_t if2 = (unsigned long) addrptr2.s_addr;
  uint32_t if3 = (unsigned long) addrptr3.s_addr;
 
  return  ((d == if1) || (d==if2) || ( d==if3));
}

/*Returns interface of IP given, empty string
  if not ours*/
char* checkRTable(struct sr_instance* sr, uint32_t dest_ip){
  struct sr_rt* rt_walker;
  rt_walker = sr->routing_table;
  if(rt_walker == 0){
    fprintf(stderr, "Router Table empty\n");
  }
  char* iface = "";
  if ((&(rt_walker->dest))->s_addr == dest_ip){
    iface = rt_walker->interface;
  }else{
    while(rt_walker->next){
      rt_walker = rt_walker->next;
      if ((&(rt_walker->dest))->s_addr == dest_ip){
	iface= rt_walker->interface;
      }
    }
  }
  return iface;
}

/*Flips ethernet destination mac address and source
  mac address of packet that is going to go back the
  way it came in through*/
void sendInReverse(sr_ethernet_hdr_t* out_eth,  
		   sr_ethernet_hdr_t* ethernet_hdr){
  //just swap source's MAC address with ours 
  //(this is of the router who sent it to
  //us, not the actual source)
  //uint8_t a[ETHER_ADDR_LEN];
  //uint8_t b[ETHER_ADDR_LEN];
  int i;
  for(i=0;i<ETHER_ADDR_LEN;i++){
    (out_eth->ether_dhost)[i] = (ethernet_hdr->ether_dhost)[i];
  }
  int j;
  for(j=0;j<ETHER_ADDR_LEN;j++){
    (out_eth->ether_shost)[j] = (ethernet_hdr->ether_shost)[j];
  }
  
}

/*convert from [unsigned char] -> [uint8_t]*/
void convertMAC(uint8_t dest_mac[], unsigned char mac[]){

  int i;
  for (i=0;i<ETHER_ADDR_LEN;i++){
    dest_mac[i] = (uint8_t) mac[i];
  }
  //uint8_t dest_mac[6] = arp_entry->mac;//unsigned char mac[6]
}

/*******Helpers For ICMP*************************************/ 
/*Returns ICMP type and code in 1 integer
 * If -1, then no need for ICMP protocol
 */
int icmp(struct sr_instance* sr, uint8_t* packet){
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + (uint8_t) sizeof(struct sr_ethernet_hdr));
  sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(ip_header + (uint8_t) sizeof(struct sr_ip_hdr));

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
    if (ntohs(ip_header->ip_ttl) <= 0){
      icmp_type_code = timeExceed;
    }else{
      //Check if IP address in rtable by traversing it.
      char* iface = checkRTable(sr,dest_ip);
      int s = strcmp(iface,"");
      if (s == 0){
	//means no route
	icmp_type_code = destNetUnReach;
      }
    }
  }
  return icmp_type_code;
}



/*Sets the ICMP headers of a packet, for sending purposes*/
void setIcmpHeaders(uint8_t* buf, int icmp_type_code, 
		    struct sr_instance* sr){
  int minLenIP = eth_size + sizeof(struct sr_ip_hdr);
  
  //set ethernet header fields
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)buf;
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(buf + (uint8_t) eth_size);
  sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*)buf;
  out_eth->ether_type = htons(ethertype_ip);
  //swap MAC addresses
  sendInReverse(out_eth, ethernet_hdr);
	  

  //set for IP header fields
  sr_ip_hdr_t* out_ip = (sr_ip_hdr_t*)(buf + (uint8_t) sizeof(struct sr_ethernet_hdr));
  out_ip->ip_tos = 0;
  out_ip->ip_len = htonl(out_ip->ip_len); //need to add length of data
  out_ip->ip_id = 0;
  out_ip->ip_off = 0;
  out_ip->ip_ttl = htonl(35); //default
  out_ip->ip_p = htonl(ip_protocol_icmp);
  out_ip->ip_sum = 0;
  //Go back through same interface it came through
  struct sr_if* ifRecord =(struct sr_if*)getIfRecord(sr, dest_ip);
  uint32_t new_src_IP = ifRecord->ip;  
  out_ip->ip_src = htonl(new_src_IP);
  out_ip->ip_dst =  ip_header->ip_src;
  out_ip->ip_sum = cksum(out_ip, 
		    sizeof(struct sr_ip_hdr));//should be 16 bit words
	  
  //Set ICMP header
  //st_icmp_hdr_t* out_icmp = buf + minLenIP;
 	  
  //needed for after ICMP header (for the dest)
  uint8_t* copy_buf = (uint8_t*)(malloc(sizeof(struct sr_ip_hdr) + 8*sizeof(char)));
  copy_buf = (sr_ip_hdr_t*)ip_header;
  //set fields
  if ((icmp_type_code == destNetUnReach) 
      || (icmp_type_code == destHostUnReach)
      || (icmp_type_code == portUnReach)){
    sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(buf + (uint8_t) minLenIP);
    icmp_t3_hdr->icmp_type = htons((uint8_t)3);
    if (icmp_type_code == destNetUnReach){
      icmp_t3_hdr->icmp_code = htons((uint8_t)0);
    }else if (icmp_type_code == destHostUnReach){
      icmp_t3_hdr->icmp_code = htons((uint8_t)1);
    }else{//portUnReach
      icmp_t3_hdr->icmp_code = htons((uint8_t)3);
    }
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->next_mtu = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
    //original internet header + first 64 bits of data
    int i;
    for(i=0;i<sizeof(copy_buf);i++){
      (icmp_t3_hdr->data)[i] = copy_buf[i];
    }
    
    //you'll need to free this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  }else if (icmp_type_code == echoReply){
    //we'll use a t3 header because size is same as echo reply header
    //the unused field is now the id 
    sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(buf + minLenIP);
    icmp_t3_hdr->icmp_type = htons((uint8_t)0);
    icmp_t3_hdr->icmp_code = htons((uint8_t)0);
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->next_mtu = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
    int i;
    for(i=0;i<sizeof(copy_buf);i++){
      (icmp_t3_hdr->data)[i] = copy_buf[i];
    }
    //data from original packet is put after ICMP header
    //icmp_t3_hdr->data = copy_buf;
    
  }else if (icmp_type_code == timeExceed){
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(buf + minLenIP);
    icmp_hdr->icmp_type = htons((uint8_t)11);
    icmp_hdr->icmp_code = htons((uint8_t)0);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_hdr));
    int i;
    for(i=0;i<sizeof(copy_buf);i++){
      (buf + (uint8_t) minLenIP + (uint8_t) sizeof(struct sr_icmp_hdr))[i] = copy_buf[i];
    }
  }else{
    //pass
  }
}



/*****************Packet Sending*******************/

/*sends packet, checks any errors and frees buffer
 */
void sendPacket(struct sr_instance* sr, uint8_t* buf, char* iface, int len){
  //send out icmp packet now
  //Send packet
  int ret = sr_send_packet(sr, buf, len, iface);
  if (ret != 0){
    fprintf(stderr, "Didn't send packet properly\n");
  }
  free(buf);
 
}

/*
 *This function is only called from the arp cache handler, and is done so
 *when five (5) arp requests have been sent without a response
 */
void sendIcmpHostUnreachable(struct sr_instance *sr, 
			     uint8_t*buf, 
			     char* iface, 
			     int len){
  int destHostUnReach = 0x0301ffff;//type 3,code 1
  setIcmpHeaders(buf, destHostUnReach, sr);
  sendPacket(sr,buf,iface, len);
}


/*forwards normal IP packet, returns 1 on success*/
int ip_forward(struct sr_instance* sr,
	       uint8_t* packet,
	       int len,
	       struct sr_ethernet_hdr* ethernet_hdr, 
	       uint8_t dest_mac[], 
	       uint32_t dest_ip,
	       uint16_t cksum,
	       char* interface){
   
   //reuse some of old contents, change some
  //uint8_t a[ETHER_ADDR_LEN];
  int j;
  for(j=0;j<ETHER_ADDR_LEN;j++){
    (ethernet_hdr->ether_dhost)[j] = dest_mac[j];
  }
  struct sr_if* ifRecord = (struct sr_if*)getIfRecord(sr, dest_ip);
 
   //unsigned char addr[ETHER_ADDR_LEN]
   uint8_t addr[ETHER_ADDR_LEN];
   convertMAC(addr, ifRecord->addr);
   //int j;
   for (j=0;j<ETHER_ADDR_LEN;j++){
     (ethernet_hdr->ether_shost)[j] = addr[j];
   }
   sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + (uint8_t)eth_size);
   ip_header->ip_sum = htonl(modCksum);
	    
   //Send packet
   int ret = sr_send_packet(sr, packet, len, interface);
   if (ret != 0){
     fprintf(stderr, "Didn't send packet properly\n");
   }
  return ret;
}

/*Sends ARP reply packet, returns 1 if success*/
int arp_send(struct sr_instance* sr,
	     uint8_t* packet,
	     int len,
	     struct sr_ethernet_hdr* ethernet_hdr, 
	     struct sr_arp_hdr* arp_header,
	     uint32_t dest_ip){
   //swap MAC addresses
  sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*)ethernet_hdr;
  sendInReverse(out_eth, ethernet_hdr);
	  
  //process request, send ARP reply
  arp_header->ar_op = htonl(arp_op_reply);
  arp_header->ar_tip = arp_header->ar_sip;
  struct sr_if* ifRecord = (struct sr_if*)getIfRecord(sr, dest_ip);
  arp_header->ar_sip = htonl(ifRecord->ip);
  int j;
  for(j=0;j<ETHER_ADDR_LEN;j++){
    (arp_header->ar_tha)[j] = (arp_header->ar_sha)[j];
  }
  //arp_header->ar_tha = arp_header->ar_sha;
  //convert_MAC();
  //unsigned char arp;
  //int j;
  for(j=0;j<6;j++){
    (arp_header->ar_sha)[j] = (ifRecord->addr)[j];
  }
  //unsigned char ar_sha[ETHER_ADDR_LEN]
  //addr unsigned char addr[etheraddrlen]


  //Send packet
  int ret = sr_send_packet(sr, packet, len, ifRecord->name);
  if (ret != 0){
    fprintf(stderr, "Didn't send arp packet properly\n");
  }
  return ret;
}


/******************************Handles incoming packets*/
/*Handles all incoming IP packets, returns 1 if successful*/
int handle_IP_packet(struct sr_instance* sr, 
		      uint8_t* packet,
		      int len, 
		      char* interface){
  int normal_ip_forward = 0;
  int icmp_send = 0;
  struct sr_ethernet_hdr* ethernet_hdr =  (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + (uint8_t) eth_size);
  int minLenIP = eth_size + sizeof(struct sr_ip_hdr);
  
  //1. Basic Standards: Make  sure it meets min len of packet,
  //   check checksum correct; set drop_packet if necessary
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

  //2. Figure out if either drop packet, or ICMP neccessary, 
  //   or just IP forward
  if (drop_packet == 0){
    dest_ip = ntohl(ip_header->ip_dst);
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
   
  //if going to ip forward -> recompute ttl
  if (normal_ip_forward == 1){
    //ttl--, recompute checksum over modifified header
    ip_header->ip_ttl = htonl(ntohs(ip_header->ip_ttl) - 1);
    modCksum = cksum(ip_header, sizeof(struct sr_ip_hdr));
  }

  //if not dropping
  if (drop_packet == 0){
    //check arp cache for mac address
    struct sr_arpentry *arp_entry;
    arp_entry = sr_arpcache_lookup(&(sr->cache),
				   htonl(ip_header->ip_dst));

    //Means we found the ARP entry
    if (arp_entry != NULL){
      uint8_t dest_mac[ETHER_ADDR_LEN];
      convertMAC(dest_mac, arp_entry->mac);

      //use this to send to next hop ip, free entry
      free(arp_entry);
	
      //ICMP
      if (icmp_send == 1){
	//send back to source IP
	//Create Ethernet header, IP header and ICMP header
	int buff_size = minLenIP 
	  + sizeof(struct sr_icmp_t3_hdr) + ICMP_DATA_SIZE;//plus more?
	uint8_t* buf = (uint8_t*)malloc(buff_size);
	  
	setIcmpHeaders(buf, icmp_type_code, sr);
	sendPacket(sr,buf, interface, buff_size); //????????

      }else{
	if (normal_ip_forward == 1){
	  //means no errors detected; thus send packet
	  int ret = ip_forward(sr,packet,len,ethernet_hdr,
			       dest_mac,dest_ip,modCksum,interface);
	  if (ret!= 0){
	    fprintf(stderr, "Didn't send ip packet properly\n");
	    //return;
	  }
	}
      }
    }else{
      //entry not found ARP cache
      struct sr_arpreq* req1;
      req1 = (struct sr_arpreq*)(arpcache_queuereq(htonl(dest_ip),packet,len));
      free(req1);
      //rest done by arp_cahce. functions
      //ARP reply process code handles this
    }
  }//else packets are ignored (drop packet)
  return 1;
}

/*Does all handling of incoming ARP packets, returns 1 if successful*/
int handle_ARP_packet(struct sr_instance* sr, 
		      uint8_t* packet,
		      int len, 
		      char* interface){
  int minLenARP = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr); 
  if (len < minLenARP){
      fprintf(stderr, "Failed to access ARP header, too small\n");
      drop_packet = 1;
      //return;
    }
    if (drop_packet == 0){
      if (destinedToRouter(dest_ip)){
	sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + (uint8_t) eth_size);

	if (ntohl(arp_header->ar_op) == arp_op_reply){//We have a ARP reply
	  //process reply
	  //move entries from ARP request queue to ARP cache
	  struct sr_arpreq* req;
	  req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha,
				   ntohl(arp_header->ar_sip));
	  if (req!=NULL){
	     struct sr_packet* traverser = req->packets;
	     while(traverser != NULL){
	       //normal IP forward, no errors detected
	       //change old contents
	       struct sr_arpentry *arp_entry;
	       arp_entry = sr_arpcache_lookup(&(sr->cache),dest_ip);
	       sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + (uint8_t) eth_size);
	       sr_ethernet_hdr_t* out_eth = (sr_ethernet_hdr_t*)packet;
	       uint16_t modCksum = cksum(ip_header, sizeof(struct sr_ip_hdr));
	       int ret = ip_forward(sr,packet,len,out_eth,arp_entry->mac,
				    dest_ip, modCksum,interface);
	       if (ret!= 0){
		 fprintf(stderr, "Didn't send ip packet properly\n");

	       }

	       traverser = traverser->next;
	     }
	     sr_arpreq_destroy(&(sr->cache), req);
	  }
	}else{
	  //process ARP request and send reply 
	  //(they want our MAC address) so sends reply packet
	  int ret =  arp_send(sr,packet,len,
			      ethernet_hdr,arp_header,dest_ip);
	  if (ret!= 0){
	    fprintf(stderr, "Didn't send arp packet properly\n");

	  }
	}
      }else{
	//pass
	//forward packet
      }
    }
    return 1;
}
