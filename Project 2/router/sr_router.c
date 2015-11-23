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
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define MIN_IP_HEADER_LENGTH  (5)
#define DEFAULT_TTL           (64)
#define SUPPORTED_IP_VERSION  (4)

#define GET_ETHERNET_DEST_ADDR(pktPtr)    (((sr_ethernet_hdr_t*)pktPtr)->ether_dhost)

#ifdef DONT_DEFINE_UNLESS_DEBUGGING
# define LOG_MESSAGE(...) fprintf(stderr, __VA_ARGS__)
#else 
# define LOG_MESSAGE(...)
#endif

static uint16_t ipIdentifyNumber = 0;

static const uint8_t broadcastEthernetAddress[ETHER_ADDR_LEN] =
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void link_handle_rcvd_arp_pkt(struct sr_instance* sr, sr_arp_hdr_t* packet,
   unsigned int length, sr_if_t const * const interface);
static void link_arp_send_pkt(struct sr_instance* sr, sr_ethernet_hdr_t* packet,
   unsigned int length, sr_rt_t const * const route);
static void netwrk_handle_rcvd_ip_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, sr_if_t const * const interface);
static void netwrk_handle_icmp_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, sr_if_t const * const interface);
static void netwrk_send_icmp_echo(struct sr_instance* sr, sr_ip_hdr_t* echoRequestPacket,
   unsigned int length);
static void netwrk_send_icmp_ttl(struct sr_instance* sr, sr_ip_hdr_t* originalPacket,
   unsigned int length, sr_if_t const * const rcvd_interface);
static bool netwrk_ip_src_check(struct sr_instance* sr, sr_ip_hdr_t const * const packet);
static int netwrk_get_mask_len(uint32_t mask);

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

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int length,
   char* interface/* lent */)
{
   struct sr_if* rcvd_interfaceEntry = NULL;
   
   /* REQUIRES */
   assert(sr);
   assert(packet);
   assert(interface);
   
   printf("*** -> Received packet of length %d \n", length);
   print_hdrs(packet, length);
   
   /* fill in code here */
   
   if (length < sizeof(sr_ethernet_hdr_t))
   {
      /* Ummm...this packet doesn't appear to be long enough to 
       * process... Drop it like it's hot! */
      return;
   }
   
   rcvd_interfaceEntry = sr_get_interface(sr, interface);
   
   if ((rcvd_interfaceEntry == NULL)
      || ((memcmp(GET_ETHERNET_DEST_ADDR(packet), rcvd_interfaceEntry->addr, ETHER_ADDR_LEN) != 0)
         && (memcmp(GET_ETHERNET_DEST_ADDR(packet), broadcastEthernetAddress, ETHER_ADDR_LEN) != 0)))
   {
      /* Packet not sent to our Ethernet address? */
      LOG_MESSAGE("Dropping packet due to invalid Ethernet receive parameters.\n");
      return;
   }
   
   switch (ethertype(packet))
   {
      case ethertype_arp:
         /* Pass the packet to the next layer, strip the low level header. */
         link_handle_rcvd_arp_pkt(sr, (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)),
            length - sizeof(sr_ethernet_hdr_t), rcvd_interfaceEntry);
         break;
         
      case ethertype_ip:
         /* Pass the packet to the next layer, strip the low level header. */
         netwrk_handle_rcvd_ip_pkt(sr, (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)),
            length - sizeof(sr_ethernet_hdr_t), rcvd_interfaceEntry);
         break;
         
      default:
         /* We have no logic to handle other packet types. Drop the packet! */
         LOG_MESSAGE("Dropping packet due to invalid Ethernet message type: 0x%X.\n", ethertype(packet));
         return;
   }

}/* end sr_handlepacket */

void sr_link_send_arp_req(struct sr_instance* sr, struct sr_arpreq* request)
{
   uint8_t* arp_pkt = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
   sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arp_pkt;
   sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (arp_pkt + sizeof(sr_ethernet_hdr_t));
   assert(arp_pkt);
   
   LOG_MESSAGE("ARPing %u.%u.%u.%u on %s\n", (request->ip >> 24) & 0xFF, 
      (request->ip >> 16) & 0xFF, (request->ip >> 8) & 0xFF, request->ip & 0xFF, 
      request->requestedInterface->name);
   
   /* Ethernet Header */
   memcpy(ethernetHdr->ether_dhost, broadcastEthernetAddress, ETHER_ADDR_LEN);
   memcpy(ethernetHdr->ether_shost, request->requestedInterface->addr, ETHER_ADDR_LEN);
   ethernetHdr->ether_type = htons(ethertype_arp);
   
   /* ARP Header */
   arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
   arp_hdr->ar_pro = htons(ethertype_ip);
   arp_hdr->ar_hln = ETHER_ADDR_LEN;
   arp_hdr->ar_pln = IP_ADDR_LEN;
   arp_hdr->ar_op = htons(arp_op_request);
   memcpy(arp_hdr->ar_sha, request->requestedInterface->addr, ETHER_ADDR_LEN);
   arp_hdr->ar_sip = request->requestedInterface->ip;
   memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN); /* Not strictly necessary by RFC 826 */
   arp_hdr->ar_tip = htonl(request->ip);
   
   /* Ship it! */
   sr_send_packet(sr, arp_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
      request->requestedInterface->name);
   
   free(arp_pkt);
}

void sr_ip_send_type_three_icmp_pkt(struct sr_instance* sr, sr_icmp_code_t icmpCode,
   sr_ip_hdr_t* origin_pkt_ptr)
{
   struct sr_rt* icmpRoute;
   struct sr_if* destinationInterface;
   
   uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
      + sizeof(sr_icmp_t3_hdr_t));
   sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
   sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
      + sizeof(sr_ip_hdr_t));
   
   assert(origin_pkt_ptr);
   assert(sr);
   assert(replyPacket);
   
   if (netwrk_ip_src_check(sr, origin_pkt_ptr))
   {
      LOG_MESSAGE("Attempted to send Destination Unreachable ICMP packet to ourself.\n");
      free(replyPacket);
      return;
   }
   
   /* Fill in IP header */
   replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
   replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
   replyIpHeader->ip_tos = 0;
   replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
   replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
   replyIpHeader->ip_off = htons(IP_DF);
   replyIpHeader->ip_ttl = DEFAULT_TTL;
   replyIpHeader->ip_p = ip_protocol_icmp;
   replyIpHeader->ip_sum = 0;
   replyIpHeader->ip_dst = origin_pkt_ptr->ip_src; /* Already in network byte order. */
   
   /* PAUSE. We need to get the destination interface. API has enough 
    * information to get it now. */
   icmpRoute = ip_get_pkt_rte(sr, ntohl(replyIpHeader->ip_dst));
   assert(icmpRoute);
   destinationInterface = sr_get_interface(sr, icmpRoute->interface);
   assert(destinationInterface);
   
   /* Okay, RESUME. */
   replyIpHeader->ip_src = destinationInterface->ip;
   replyIpHeader->ip_sum = cksum(replyIpHeader, get_ip_header_len(replyIpHeader));
   
   /* Fill in ICMP fields. */
   replyIcmpHeader->icmp_type = icmp_type_desination_unreachable;
   replyIcmpHeader->icmp_code = icmpCode;
   replyIcmpHeader->icmp_sum = 0;
   memcpy(replyIcmpHeader->data, origin_pkt_ptr, ICMP_DATA_SIZE);
   replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
   
   link_arp_send_pkt(sr, (sr_ethernet_hdr_t*) replyPacket,
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
      ip_get_pkt_rte(sr, ntohl(replyIpHeader->ip_dst)));
   
   free(replyPacket);

}

void sr_ip_handle_received_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, sr_if_t const * const interface)
{
   /* Somebody must like me, because they're sending packets to my 
    * address! */
   if (packet->ip_p == (uint8_t) ip_protocol_icmp)
   {
      netwrk_handle_icmp_pkt(sr, packet, length, interface);
   }
   else
   {
      /* I don't process anything else! Send port unreachable. */
      LOG_MESSAGE("Received Non-ICMP packet destined for me. Sending ICMP port unreachable.\n");
      sr_ip_send_type_three_icmp_pkt(sr, icmp_code_destination_port_unreachable, packet);
   }
}


void ip_frwd_ip_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const rcvd_interface)
{
   struct sr_rt* forwardRoute = ip_get_pkt_rte(sr, ntohl(packet->ip_dst));
   /* Decrement TTL and forward. */
   uint8_t packetTtl = packet->ip_ttl - 1;
   if (packetTtl == 0)
   {
      /* Uh oh... someone's just about run out of time. */
      netwrk_send_icmp_ttl(sr, packet, length, rcvd_interface);
      return;
   }
   else
   {
      /* Recalculate checksum since we altered the packet header. */
      packet->ip_ttl = packetTtl;
      packet->ip_sum = 0;
      packet->ip_sum = cksum(packet, get_ip_header_len(packet));
   }
   

   if (forwardRoute != NULL)
   {
      /* We found a viable route. Forward to it! */
      uint8_t* forwardPacket = malloc(length + sizeof(sr_ethernet_hdr_t));
      memcpy(forwardPacket + sizeof(sr_ethernet_hdr_t), packet, length);
      
      LOG_MESSAGE("Forwarding from interface %s to %s\n", rcvd_interface->name, 
         forwardRoute->interface);
   
      link_arp_send_pkt(sr, (sr_ethernet_hdr_t*)forwardPacket,
         length + sizeof(sr_ethernet_hdr_t), forwardRoute);
      
      free(forwardPacket);
   }
   else
   {
      LOG_MESSAGE("Routing decision could not be made. Sending ICMP network unreachable.\n");
      sr_ip_send_type_three_icmp_pkt(sr, icmp_code_network_unreachable, packet);
   }
}

sr_rt_t* ip_get_pkt_rte(struct sr_instance* sr, in_addr_t destIp)
{
   struct sr_rt* routeIter;
   int networkMaskLength = -1;
   struct sr_rt* ret = NULL;
   
   for (routeIter = sr->routing_table; routeIter; routeIter = routeIter->next)
   {
      /* Assure the route we are about to check has a longer mask then the 
       * last one we chose.  This is so we can find the longest prefix match. */
      if (netwrk_get_mask_len(routeIter->mask.s_addr) > networkMaskLength)
      {
         /* Mask is longer, now see if the destination matches. */
         if ((destIp & routeIter->mask.s_addr) 
            == (ntohl(routeIter->dest.s_addr) & routeIter->mask.s_addr))
         {
            /* Longer prefix match found. */
            ret = routeIter;
            networkMaskLength = netwrk_get_mask_len(routeIter->mask.s_addr);
         }
      }
   }
   
   return ret;
}

bool icmp_integrity_check(sr_icmp_hdr_t * const icmp_pkt, unsigned int length)
{
   /* Check the integrity of the ICMP packet */
   uint16_t headerChecksum = icmp_pkt->icmp_sum;
   uint16_t calculatedChecksum = 0;
   icmp_pkt->icmp_sum = 0;
   
   calculatedChecksum = cksum(icmp_pkt, length);
   icmp_pkt->icmp_sum = headerChecksum;
   
   if (headerChecksum != calculatedChecksum)
   {
      /* Bad checksum... */
      return false;
   }
   return true;
}

bool tcp_integrity_check(sr_ip_hdr_t * const tcp_pkt, unsigned int length)
{
   bool ret;
   unsigned int tcpLength = length - get_ip_header_len(tcp_pkt);
   uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   sr_tcp_ip_pseudo_hdr_t * checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
   sr_tcp_hdr_t * const tcpHeader = (sr_tcp_hdr_t * const ) (((uint8_t*) tcp_pkt)
      + get_ip_header_len(tcp_pkt));
   
   uint16_t calculatedChecksum = 0;
   uint16_t headerChecksum = tcpHeader->checksum;
   tcpHeader->checksum = 0;
   

   memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);
   checksummedHeader->sourceAddress = tcp_pkt->ip_src;
   checksummedHeader->destinationAddress = tcp_pkt->ip_dst;
   checksummedHeader->zeros = 0;
   checksummedHeader->protocol = ip_protocol_tcp;
   checksummedHeader->tcpLength = htons(tcpLength);
   
   calculatedChecksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   
   ret = (headerChecksum == calculatedChecksum) ? true : false; 
   
   free(packetCopy);
   
   return ret;
}

bool ip_dest_check(struct sr_instance* sr, const sr_ip_hdr_t* const packet)
{
   struct sr_if* interfaceIterator;
   
   for (interfaceIterator = sr->if_list; interfaceIterator != NULL; interfaceIterator =
      interfaceIterator->next)
   {
      if (packet->ip_dst == interfaceIterator->ip)
      {
         return true;
      }
   }
   
   return false;
}

static void link_handle_rcvd_arp_pkt(struct sr_instance* sr, sr_arp_hdr_t * packet,
   unsigned int length, const struct sr_if* const interface)
{
   if (length < sizeof(sr_arp_hdr_t))
   {
      /* Not big enough to be an ARP packet... */
      return;
   }
   
   if ((ntohs(packet->ar_pro) != ethertype_ip)
      || (ntohs(packet->ar_hrd) != arp_hrd_ethernet)
      || (packet->ar_pln != IP_ADDR_LEN) 
      || (packet->ar_hln != ETHER_ADDR_LEN))
   {
      /* Received unsupported packet argument */
      LOG_MESSAGE("ARP packet received with invalid parameters. Dropping.\n");
      return;
   }
   
   switch (ntohs(packet->ar_op))
   {
      case arp_op_request:
      {
         if (packet->ar_tip == interface->ip)
         {
            /* We're being ARPed! Prepare the reply! */
            uint8_t* replyPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
            sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));
            
            LOG_MESSAGE("Received ARP request. Sending ARP reply.\n");
            
            /* Ethernet Header */
            memcpy(ethernetHdr->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);
            memcpy(ethernetHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            ethernetHdr->ether_type = htons(ethertype_arp);
            
            /* ARP Header */
            arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            arp_hdr->ar_pro = htons(ethertype_ip);
            arp_hdr->ar_hln = ETHER_ADDR_LEN;
            arp_hdr->ar_pln = IP_ADDR_LEN;
            arp_hdr->ar_op = htons(arp_op_reply);
            memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = interface->ip;
            memcpy(arp_hdr->ar_tha, packet->ar_sha, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = packet->ar_sip;
            
            sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
               interface->name);
            
            free(replyPacket);
         }
         break;
      }
      
      case arp_op_reply:
      {

         if (packet->ar_tip == interface->ip)
         {
            struct sr_arpreq* requestPointer = sr_arpcache_insert(
               &sr->cache, packet->ar_sha, ntohl(packet->ar_sip));
            
            if (requestPointer != NULL)
            {
               LOG_MESSAGE("Received ARP reply, sending all queued packets.\n");
               
               while (requestPointer->packets != NULL)
               {
                  struct sr_packet* curr = requestPointer->packets;
                  
                  /* Copy in the newly discovered Ethernet address of the frame */
                  memcpy(((sr_ethernet_hdr_t*) curr->buf)->ether_dhost,
                     packet->ar_sha, ETHER_ADDR_LEN);
                  
                  /* The last piece of the pie is now complete. Ship it. */
                  sr_send_packet(sr, curr->buf, curr->len, curr->iface);
                  
                  /* Forward list of packets. */
                  requestPointer->packets = requestPointer->packets->next;
                  
                  /* Free all memory associated with this packet (allocated on queue). */
                  free(curr->buf);
                  free(curr->iface);
                  free(curr);
               }
               
               /* Bye bye ARP request. */
               sr_arpreq_destroy(&sr->cache, requestPointer);
            }
            else
            {
               /* Queued response to one of our ARP request retries? */
               LOG_MESSAGE("Received ARP reply, but found no request.\n");
            }
         }
         break;
      }
      
      default:
      {
         /* Unrecognized ARP type */
         LOG_MESSAGE("Received packet with invalid ARP type: 0x%X.\n", ntohs(packet->ar_op));
         break;
      }
   }
}

static void netwrk_handle_rcvd_ip_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface)
{
   if (length < sizeof(sr_ip_hdr_t))
   {
      /* Not big enough to be an IP packet... */
      LOG_MESSAGE("Received IP packet with invalid length. Dropping.\n");
      return;
   }
   
   if (packet->ip_hl >= MIN_IP_HEADER_LENGTH)
   {
      uint16_t headerChecksum = packet->ip_sum;
      uint16_t calculatedChecksum = 0;
      packet->ip_sum = 0;
      
      calculatedChecksum = cksum(packet, get_ip_header_len(packet));
      
      if (headerChecksum != calculatedChecksum)
      {
         /* Bad checksum */
         LOG_MESSAGE("IP checksum failed. Dropping received packet.\n");
         return;
      }
      else
      {
         /* Put it back. This is so if we send an ICMP message which contains 
          * this packet's header, it can be as we received it. */
         packet->ip_sum = headerChecksum;
      }
   }
   else
   {
      /* Something is way wrong with this packet. Throw it out. */
      LOG_MESSAGE("Received IP packet with invalid length in header. Dropping.\n");
      return;
   }
   
   if (packet->ip_v != SUPPORTED_IP_VERSION)
   {
      /* What do you think we are? Some fancy, IPv6 router? Guess again! 
       * Process IPv4 packets only.*/
      LOG_MESSAGE("Received non-IPv4 packet. Dropping.\n");
      return;
   }
   
   if (ip_dest_check(sr, packet))
      sr_ip_handle_received_pkt(sr, packet, length, interface);
   else
      ip_frwd_ip_pkt(sr, packet, length, interface);
}

static void netwrk_handle_icmp_pkt(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface)
{
   sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (((uint8_t*) packet) + get_ip_header_len(packet));
   int icmpLength = length - get_ip_header_len(packet);
   
   if (!icmp_integrity_check(icmpHeader, icmpLength))
   {
      LOG_MESSAGE("ICMP checksum failed. Dropping received packet.\n");
      return;
   }
   
   if (icmpHeader->icmp_type == icmp_type_echo_request)
   {
     /* Send an echo Reply!*/ 
      netwrk_send_icmp_echo(sr, packet, length);
   }
   else
   {
   /* I don't send any non-ICMP packets...How did I receive another ICMP type?*/
      LOG_MESSAGE("Received unexpected ICMP message. Type: %u, Code: %u\n", 
         icmpHeader->icmp_type, icmpHeader->icmp_code);
   }
}

static void netwrk_send_icmp_echo(struct sr_instance* sr, sr_ip_hdr_t* echoRequestPacket,
   unsigned int length)
{
   int icmpLength = length - get_ip_header_len(echoRequestPacket);
   uint8_t* replyPacket = malloc(icmpLength + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
   sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
   sr_icmp_hdr_t* replyIcmpHeader =
      (sr_icmp_hdr_t*) ((uint8_t*) replyIpHeader + sizeof(sr_ip_hdr_t));
   assert(replyPacket);
   
   LOG_MESSAGE("Received ICMP echo request packet. Sending ICMP echo reply.\n");
   
   /* Fill in IP Header fields. */
   replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
   replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
   replyIpHeader->ip_tos = 0;
   replyIpHeader->ip_len = htons((uint16_t) length);
   replyIpHeader->ip_id = htons(ipIdentifyNumber);
   ipIdentifyNumber++;
   replyIpHeader->ip_off = htons(IP_DF);
   replyIpHeader->ip_ttl = DEFAULT_TTL;
   replyIpHeader->ip_p = ip_protocol_icmp;
   replyIpHeader->ip_sum = 0;
   replyIpHeader->ip_src = echoRequestPacket->ip_dst; /* Already in network byte order. */
   replyIpHeader->ip_dst = echoRequestPacket->ip_src; /* Already in network byte order. */
   replyIpHeader->ip_sum = cksum(replyIpHeader, get_ip_header_len(replyIpHeader));
   
   /* Fill in ICMP fields. */
   replyIcmpHeader->icmp_type = icmp_type_echo_reply;
   replyIcmpHeader->icmp_code = 0;
   replyIcmpHeader->icmp_sum = 0;
   
   /* Copy the old payload into the new one... */
   memcpy(((uint8_t*) replyIcmpHeader) + sizeof(sr_icmp_hdr_t),
      ((uint8_t*) echoRequestPacket) + get_ip_header_len(echoRequestPacket) + sizeof(sr_icmp_hdr_t), 
      icmpLength - sizeof(sr_icmp_hdr_t));
   
   /* ...then update the final checksum for the ICMP payload. */
   replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, icmpLength);
   
   /* Reply payload built. Ship it! */
   link_arp_send_pkt(sr, (sr_ethernet_hdr_t*) replyPacket, length + sizeof(sr_ethernet_hdr_t),
      ip_get_pkt_rte(sr, ntohl(echoRequestPacket->ip_src)));
   
   free(replyPacket);
}

static void netwrk_send_icmp_ttl(struct sr_instance* sr, sr_ip_hdr_t* originalPacket,
   unsigned int length, sr_if_t const * const rcvd_interface)
{
   uint8_t* replyPacket = malloc(
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
   sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
   sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
      + sizeof(sr_ip_hdr_t));
   
   /*if (natEnabled(sr))
   {
      NatUndoPacketMapping(sr, originalPacket, length, rcvd_interface);
      }*/
   
   LOG_MESSAGE("TTL expired on received packet. Sending an ICMP time exceeded.\n");
   
   /* Fill in IP header */
   replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
   replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
   replyIpHeader->ip_tos = 0;
   replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
   replyIpHeader->ip_id = htons(ipIdentifyNumber);
   ipIdentifyNumber++;
   replyIpHeader->ip_off = htons(IP_DF);
   replyIpHeader->ip_ttl = DEFAULT_TTL;
   replyIpHeader->ip_p = ip_protocol_icmp;
   replyIpHeader->ip_sum = 0;
   replyIpHeader->ip_src = rcvd_interface->ip;
   replyIpHeader->ip_dst = originalPacket->ip_src; /* Already in network byte order. */
   replyIpHeader->ip_sum = cksum(replyIpHeader, get_ip_header_len(replyIpHeader));
   
   /* Fill in ICMP fields. */
   replyIcmpHeader->icmp_type = icmp_type_time_exceeded;
   replyIcmpHeader->icmp_code = 0;
   replyIcmpHeader->icmp_sum = 0;
   memcpy(replyIcmpHeader->data, originalPacket, ICMP_DATA_SIZE);
   replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
   
   link_arp_send_pkt(sr, (sr_ethernet_hdr_t*) replyPacket,
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
      ip_get_pkt_rte(sr, ntohl(originalPacket->ip_src)));
   
   free(replyPacket);
}

static void link_arp_send_pkt(sr_instance_t *sr, sr_ethernet_hdr_t* packet, 
   unsigned int length, sr_rt_t const * const route)
{
   uint32_t nextHopIpAddress;
   sr_arpentry_t *arpEntry;
   
   assert(route);
   
   /* Need the gateway IP to do the ARP cache lookup. */
   nextHopIpAddress = ntohl(route->gw.s_addr);
   arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIpAddress);
   
   /* This function is only for IP packets, fill in the type */
   packet->ether_type = htons(ethertype_ip);
   memcpy(packet->ether_shost, sr_get_interface(sr, route->interface)->addr, ETHER_ADDR_LEN);
   
   if (arpEntry != NULL)
   {
      memcpy(packet->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) packet, length, route->interface);
      
      /* Lookup made a copy, so we must free it to prevent leaks. */
      free(arpEntry);
   }
   else
   {
      /* We need to ARP our next hop. Setup the request and send the ARP packet. */
      struct sr_arpreq* arpRequestPtr = sr_arpcache_queuereq(&sr->cache, nextHopIpAddress,
         (uint8_t*) packet, length, route->interface);
      
      if (arpRequestPtr->times_sent == 0)
      {
         /* New request. Send the first ARP NOW! */
         arpRequestPtr->requestedInterface = sr_get_interface(sr, route->interface);
         
         sr_link_send_arp_req(sr, arpRequestPtr);
         
         arpRequestPtr->times_sent = 1;
         arpRequestPtr->sent = time(NULL);
      }
   }
}

static bool netwrk_ip_src_check(struct sr_instance* sr, const sr_ip_hdr_t* const packet)
{
   struct sr_if* interfaceIterator;
   
   for (interfaceIterator = sr->if_list; interfaceIterator != NULL; interfaceIterator =
      interfaceIterator->next)
   {
      if (packet->ip_src == interfaceIterator->ip)
      {
         return true;
      }
   }
   
   return false;
}

static int netwrk_get_mask_len(uint32_t mask)
{
   int ret = 0;
   uint32_t bitScanner = 0x80000000;
   
   while ((bitScanner != 0) && ((bitScanner & mask) != 0))
   {
      bitScanner >>= 1;
      ret++;
   }
   
   return ret;
}
