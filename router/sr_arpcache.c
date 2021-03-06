 
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

unsigned char* getIfRecord(struct sr_instance *sr, uint32_t ip_dest){
  char* iface =  checkRtable(sr, ip_dest);
  struct sr_if* ifRecord = sr_get_interface(sr, iface);
  return ifRecord;
}

void sendARPRequest(struct sr_instance *sr, struct sr_arpreq* request){
  
  //memory for ethernet and ARP header 
  int buff_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  uint8_t* buf = malloc(buff_size);

 
  sr_ethernet_hdr_t* eth = buf;
  struct sr_if* ifRecord = getIfRecord(sr, request->ip);
  eth->ether_shost = ifRecord->addr;
  eth->ether_type = htons(ethertype_arp);
  out_eth->ether_dhost = ['ff', 'ff', 'ff', 'ff', 'ff', 'ff'];
  //set ARP header for ARP request 
  sr_arp_hdr_t* arp_hdr = buf + sizeof(struct sr_ethernet_hdr);
  arp_hdr->ar_hrd = htonl(arp_hrd_ethernet);
  arp_hdr->ar_pro = htonl(0x0800);
  arp_hdr->ar_hln = htonl(ETHER_ADDR_LEN);
  arp_hdr->ar_pln = htonl(4);
  arp_hdr->op = htonl(arp_op_request);
  arp_hdr->ar_sha = mac;
  arp_hdr->ar_sip = htonl(srcIP);
  arp_hdr->ar_tha = 0;//need to determine
  arp_hdr->ar_tip = htonl(request->ip);
  
  //Create packet to send
  struct sr_packet* packet = malloc(sizeof(struct sr_packet));
  packet->buf = buf;
  packet->len = htonl(buff_size);
  packet->iface = iface;
  packet->next = NULL;
  //Send packet
  int ret = sr_send_packet(sr, packet, buff_size, packet->iface);
  if (ret != 0){
    perror("packet not sent");
    exit(1);
  }
}



/*Handles an arp cache request. Removes if neccessary.
 *Called by sr_arpcache_sweepreqs function for each 
 *request.
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq* request){
  struct sr_arpcache* cache = &(sr->cache);
  if (request->sent > 0){
      //sent = time; if sent= 0, then never sent
    if (request->times_sent >= 5){
     
      //send icmp host unreachable to all packets what were
      //waiting for this failed request
      //go through each packet
      struct sr_packet* traverser = request->packets;
      while(traverser != NULL){
	sendIcmpHostUnreachable(sr, traverser->buf,traverser->iface, traverser->len);
	  
	traverser = packets->next;
      }
      
      sr_arpreq_destroy(cache, request);
    }else{
      //sr_ethernet_hdr_t* eth_hdr;
      sendARPRequest(sr,request);
      
      traverser->sent = time(NULL);
      traverser->times_sent++;
    }
  }
 
}


/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
  //for each request on sr->cache.requests:
  //    handle_arpreq(request)...this could destory current request
  //        so save next ptr before calling this when traversing through
  //        ARP requests linked list
  struct sr_arpcache cache = sr->cache;
  //linked list of requests
  struct sr_arpreq* requests_root = cache.requests;
  
  //traverse cache requests
  //struct sr_arpreq* traverser = requests_root;
  
  
  struct sr_arpreq *req;
  struct sr_arpreq *next_req = requests_root->next;
  for (req = requests_root; req != NULL; req = next_req) {
    //save incremental step, because it may get deleted
    next_req = req->next;
    handle_arpreq(sr,req);
  }
  /*
  //Find first request that isn't failed; assess it and make that the root
  while(traverser!= NULL){
    if (traverser->sent > 0){
      //sent = time; if sent= 0, then never sent
      if (traverser->times_sent >= 5){
	//TODO
	//send icmp host unreachable to all packets what were
	//waiting for this failed request
	icmpHostUnreachable();
      
	//remove request node that has failed, update linked list
	if (traverser->next == NULL){
	  free(traverser);
	  
	}else{
	  requests_root = traverser->next;
	  struct sr_arpreq* old_root = traverser;
	  free(old_root);
	  traverser = requests_root;
	}
      }else{
	//TODO
	//send out another request
	traverser->sent = time(NULL);
	traverser->times_sent++;
	//int current_node_serviced = 1;
	break;
      }
    }
 
  }

  //by now,if not null, root has been assessed; now assess rest
  struct sr_arpreq* next_node;
  if(traverser!= NULL){
    while(traverser->next != NULL){
      next_node = traverser->next;
      if (next_node->times_sent >= 5){
	//TODO
	icmpHostUnreachable();
	//bypass to next_node->next, but don't traverse to it 
	traverser->next = next_node->next;
      }else{
	//TODO
	//send out another arp request
	next_node->sent = time(NULL);
	next_node->times_sent++;
	//continue traversing
	traverser = traverser->next;
      }
    }
  }
  */

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}
