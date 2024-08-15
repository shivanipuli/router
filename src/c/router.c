/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

#define CHIROUTER_OK (0)
#define CHIROUTER_ERROR (1)

/*
 * chirouter_create_ethernet_header - Initializes the fields within an ethernet header
 *
 * This function will be called every time an ethernet header needs to be initialized. The
 * function will take in an ethhdr_t struct and will then fill in the source, destination, and
 * type. This function requires that the ethernet header is already allocated before being passed
 * as an argument.
 *
 * eth_hdr: The pre-allocated ethdr_t struct
 *
 * dst_mac: The destination MAC address
 * 
 * src_mac: The source MAC address
 * 
 * eth_type: The ethernet header type
 *
 * Returns:
 *   CHIROUTER_OK (0) on success
 */
int chirouter_create_ethernet_header(ethhdr_t *eth_hdr, uint8_t* dst_mac, uint8_t* src_mac, uint16_t eth_type)
{
    /* Setting the source MAC */
    memcpy(eth_hdr->src, src_mac, ETHER_ADDR_LEN);

    /* Setting the destination MAC */
    memcpy(eth_hdr->dst, dst_mac, ETHER_ADDR_LEN);

    /* Setting the Ethernet type */
    eth_hdr->type = htons(eth_type);

    return CHIROUTER_OK;
}

/*
 * chirouter_check_interface - Checks if a given IP address is withn the context interfaces
 *
 * This function will loop through all of the interfaces within the context and will check to
 * see if the input IP address matches one of the interface IP addresses. If the IP address is
 * found, the function will return CHIROUTER OK, otherwise it will return CHIROUTER_ERROR.
 *
 * ctx: Router context
 *
 * ip_addr: The IP address to check
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if the IP address is not found
 */
int chirouter_check_interface(chirouter_ctx_t *ctx, uint32_t ip_addr)
{
    /* Looping through all of the interfaces */
    for (int i = 0; i < ctx->num_interfaces; i++) {
        chirouter_interface_t *iface = &ctx->interfaces[i];

        /* Checking to see if the IP address matches the interface IP address */
        if (iface->ip.s_addr == ip_addr) {
            return CHIROUTER_OK;
        }
    }

    return CHIROUTER_ERROR;
}

/*
 * chirouter_forward_ip_frame - Forwards an IP frame to a given interface
 *
 * The function will create a new frame, copy the original frame into the new frame, create a new ethernet header,
 * create a new IP header, and then send the frame. The function will return CHIROUTER_OK if the frame was sent
 * successfully, otherwise it will return CHIROUTER_ERROR.
 *
 * ctx: Router context
 *
 * frame: The ethernet frame to forward
 *
 * dst_mac: The destination MAC address
 *
 * iface: The interface to forward the frame to
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if the frame was not sent
 */
int chirouter_forward_ip_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame, uint8_t *dst_mac, chirouter_interface_t *iface)
{
    /* Creating the new frame that will be sent at the end of the function */
    uint8_t *new_frame = malloc(frame->length);
    if (!new_frame) {
        chilog(ERROR, "Failed to allocate memory for forwarding IP frame");
        return CHIROUTER_ERROR;
    }

    /* Copying the original frame into the new frame */
    memcpy(new_frame, frame->raw, frame->length);

    /* Creating the ethernet header for the new frame */
    ethhdr_t *eth_hdr = (ethhdr_t *) new_frame;
    chirouter_create_ethernet_header(eth_hdr, dst_mac, iface->mac, ETHERTYPE_IP);

    /* Creating the new IP header */
    struct iphdr *ip_hdr = (struct iphdr *)(new_frame + sizeof(ethhdr_t));
    ip_hdr->ttl--;
    ip_hdr->cksum = 0;
    ip_hdr->cksum = cksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4);

    /* Checking whether the new frame was sent or not */
    int result = chirouter_send_frame(ctx, iface, new_frame, frame->length);
    free(new_frame);

    /* 0 on success, 1 if there is a failure */
    return (result == 0) ? CHIROUTER_OK : CHIROUTER_ERROR;
}

/*
 * chirouter_send_arp_reply - Sends an ARP reply to a given interface
 *
 * This function will create an ARP packet, create an ethernet header, copy the ARP packet into the frame after the
 * ethernet header, and then send the frame. The function will return CHIROUTER_OK if the frame was sent successfully 
 * and CHIROUTER_ERROR if unsucessful.
 *
 * ctx: Router context
 *
 * iface: The interface to send the ARP reply to
 *
 * arp_req: The ARP request packet
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if the frame was not sent
 */
int chirouter_send_arp_reply(chirouter_ctx_t *ctx, chirouter_interface_t *iface, arp_packet_t *arp_req)
{
    /* Creating the ARP reply packet */
    arp_packet_t arp_packet;

    /* Filling in the ARP reply fields */
    arp_packet.hrd = htons(ARP_HRD_ETHERNET);
    arp_packet.pro = htons(ETHERTYPE_IP);
    arp_packet.hln = ETHER_ADDR_LEN;
    arp_packet.pln = sizeof(struct in_addr);
    arp_packet.op = htons(ARP_OP_REPLY);

    /* Setting sender hardware and protocol addresses */
    memcpy(arp_packet.sha, iface->mac, ETHER_ADDR_LEN);
    arp_packet.spa = iface->ip.s_addr;

    /* Setting target hardware and protocol addresses from the ARP req */
    memcpy(arp_packet.tha, arp_req->sha, ETHER_ADDR_LEN);
    arp_packet.tpa = arp_req->spa;

    /* Setting the frame size and mallocing the frame */
    size_t frame_size = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    uint8_t *frame = malloc(frame_size);

    /* Memory allocation failure */
    if (!frame) {
        chilog(ERROR, "Memory allocation failed for ARP reply frame");
        return 1;
    }

    /* Creating the ethernet header */
    ethhdr_t *eth_hdr = (ethhdr_t *) frame;
    chirouter_create_ethernet_header(eth_hdr, arp_req->sha, iface->mac, ETHERTYPE_ARP);

    /* Copying the ARP reply after the ethernet header */
    memcpy(frame + sizeof(ethhdr_t), &arp_packet, sizeof(arp_packet_t));

    /* Sending and freeing the frame */
    int result = chirouter_send_frame(ctx, iface, frame, frame_size);
    free(frame);

    /* 0 on success, 1 if there is a failure */
    return (result == 0) ? CHIROUTER_OK : CHIROUTER_ERROR;
}

/*
 * chirouter_create_icmp_packet - Creates an ICMP packet
 *
 * This function will initialize the fields in an ICMP packet based on the type, code, and payload length. The function will then
 * calculate the checksum and return CHIROUTER_OK if the packet was initialized successfully.
 *
 * icmp_packet: The ICMP packet to create
 *
 * request_packet: The ICMP request packet
 *
 * type: The ICMP type
 *
 * code: The ICMP code
 *
 * payload_len: The length of the payload
 *
 * ip_hdr: The IP header
 *
 * Returns:
 *   CHIROUTER_OK (0) on success
 */
int chirouter_create_icmp_packet(icmp_packet_t *icmp_packet, icmp_packet_t *request_packet, uint8_t type, uint8_t code, size_t payload_len, struct iphdr *ip_hdr)
{
    /* Assigning the type, code, and zeroing out the checksum */
    icmp_packet->type = type;
    icmp_packet->code = code;
    icmp_packet->chksum = 0;

    /* Checking for cases that are echo request or echo reply */
    if(type == ICMPTYPE_ECHO_REQUEST || type == ICMPTYPE_ECHO_REPLY) {
        icmp_packet->echo.identifier = request_packet->echo.identifier;
        icmp_packet->echo.seq_num = request_packet->echo.seq_num;
        memcpy(icmp_packet->echo.payload, request_packet->echo.payload, payload_len);
    }

    /* Checking for cases that are destination unreachable */
    else if (type == ICMPTYPE_DEST_UNREACHABLE) {
        icmp_packet->dest_unreachable.unused = 0;
        icmp_packet->dest_unreachable.next_mtu = 0;
        memcpy(icmp_packet->dest_unreachable.payload, ip_hdr, payload_len);
    }

    /* Checking for cases when the time has been exceeded */
    else if (type == ICMPTYPE_TIME_EXCEEDED) {
        icmp_packet->time_exceeded.unused = 0;
        memcpy(icmp_packet->time_exceeded.payload, ip_hdr, payload_len);
    }

    /* Calculating the checksum */
    icmp_packet->chksum = cksum((unsigned short *)icmp_packet, ICMP_HDR_SIZE + payload_len);

    return CHIROUTER_OK;
}

/*
 * chirouter_send_icmp_reply - Creates and sends an ICMP reply
 *
 * This function will create a new frame, copy the original frame into the new frame, create a new ethernet header, 
 * create a new IP header, create a new ICMP packet, and then send the frame. The function will return CHIROUTER_OK 
 * if the frame was sent successfully and CHIROUTER_ERROR otherwise.
 *
 * ctx: Router context
 * 
 * iface: The interface to send the ICMP reply to
 * 
 * type: The ICMP type
 * 
 * code: The ICMP code
 * 
 * frame: The ethernet frame
 * 
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if the frame was not sent
 */
int chirouter_send_icmp_reply(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t type, uint8_t code, ethernet_frame_t *frame)
{
    /* Creating the IP header from the frame */
    iphdr_t *ip_hdr = (iphdr_t *)(frame->raw + sizeof(ethhdr_t));

    /* Creating the ICMP request packet */
    icmp_packet_t *icmp_request = (icmp_packet_t *)(frame->raw + sizeof(ethhdr_t) + ip_hdr->ihl * 4);

    /* Assuming the actual data length needs to be calculated dynamically */
    size_t actual_data_length = sizeof(iphdr_t) + ICMP_HDR_SIZE;
    if (type == ICMPTYPE_ECHO_REPLY) {
        actual_data_length = ntohs(ip_hdr->len) - ip_hdr->ihl * 4 - ICMP_HDR_SIZE;
    }

    /* Calculating the total length of the frame */
    size_t total_len = sizeof(ethhdr_t) + sizeof(struct iphdr) + ICMP_HDR_SIZE + actual_data_length;

    /* Creating the new frame that will be sent at the end of the function */
    uint8_t *new_frame = malloc(total_len);
    if (!new_frame) {
        chilog(ERROR, "Allocation failed for ICMP echo reply packet");
        return CHIROUTER_ERROR;
    }

    /* Creating the ethernet header for the new frame */
    struct ethhdr *eth_hdr = (struct ethhdr *)new_frame;
    chirouter_create_ethernet_header(eth_hdr, ((struct ethhdr *)(frame->raw))->src, iface->mac, ETHERTYPE_IP);

    /* Creating the new IP header */
    struct iphdr *new_ip_hdr = (struct iphdr *)(new_frame + sizeof(ethhdr_t));

    /* Copying over some of the previous data from the input IP header */
    memcpy(new_ip_hdr, ip_hdr, sizeof(iphdr_t));

    /* Assigning the fields that need to be filled in and updated */
    new_ip_hdr->src = iface->ip.s_addr;
    new_ip_hdr->dst = ip_hdr->src;
    new_ip_hdr->proto = IPPROTO_ICMP;
    new_ip_hdr->len = htons(total_len - sizeof(ethhdr_t));
    new_ip_hdr->ttl = 64;
    new_ip_hdr->cksum = 0;
    new_ip_hdr->cksum = cksum((unsigned short *)new_ip_hdr, new_ip_hdr->ihl * 4);

    /* Creating the ICMP reply packet */
    icmp_packet_t *icmp_reply = (icmp_packet_t *)(new_frame + sizeof(ethhdr_t) + sizeof(iphdr_t));
    chirouter_create_icmp_packet(icmp_reply, icmp_request, type, code, actual_data_length, ip_hdr);

    /* Checking whether the frame was sent or not */
    int result = chirouter_send_frame(ctx, iface, new_frame, total_len);
    free(new_frame);

    /* 0 on success, 1 if there is a failure */
    return (result == 0) ? CHIROUTER_OK : CHIROUTER_ERROR;
}

/*
 * chirouter_send_arp_request - Sends an ARP request
 *
 * This function will loop through all of the interfaces within the context and will send an ARP request 
 * to each interface. The function will return CHIROUTER_OK if the ARP request was sent successfully and 
 * CHIROUTER_ERROR otherwise.
 *
 * ctx: Router context
 *
 * out_iface: The interface to send the ARP request to
 *
 * ip_target: The target IP address
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if there is a malloc failure
 */
int chirouter_send_arp_request(chirouter_ctx_t *ctx, chirouter_interface_t *out_iface, struct in_addr *ip_target)
{
    /* Looping through all the interfaces */
    for (int i = 0; i < ctx->num_interfaces; i++) {
        /* Assigning the interface */
        chirouter_interface_t *iface = &ctx->interfaces[i];

        /* Creating the ARP packet*/
        arp_packet_t arp_packet;

        /* Filling in the ARP request fields */
        arp_packet.hrd = htons(ARP_HRD_ETHERNET);
        arp_packet.pro = htons(ETHERTYPE_IP);
        arp_packet.hln = ETHER_ADDR_LEN;
        arp_packet.pln = sizeof(struct in_addr);
        arp_packet.op = htons(ARP_OP_REQUEST);

        /* Setting the sender hardware and protocol addresses */
        memcpy(arp_packet.sha, iface->mac, ETHER_ADDR_LEN);
        arp_packet.spa = iface->ip.s_addr;

        /* Setting the target hardware and protocol addresses */
        memset(arp_packet.tha, 0, ETHER_ADDR_LEN);
        arp_packet.tpa = ip_target->s_addr;

        /* Mallocing the frame */
        uint8_t *frame = malloc(sizeof(ethhdr_t) + sizeof(arp_packet_t));
        if (!frame) {
            chilog(ERROR, "Memory allocation for ethernet frame failed.");
            return CHIROUTER_ERROR;
        }

        /* Creating the broadcast mac address */
        uint8_t broadcast_mac[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        /* Creatng the ethernet header */
        ethhdr_t *ethhdr = (ethhdr_t *) frame;
        chirouter_create_ethernet_header(ethhdr, broadcast_mac, iface->mac, ETHERTYPE_ARP);

        /* Copying the ARP packet after the ethernet header */
        memcpy(frame + sizeof(ethhdr_t), &arp_packet, sizeof(arp_packet_t));

        /* Checking whether the packet was sent or not */
        int result = chirouter_send_frame(ctx, iface, frame, sizeof(ethhdr_t) + sizeof(arp_packet_t));
        free(frame);
    }

    return CHIROUTER_OK;
}

/*
 * chirouter_send_withheld - Sends withheld frames
 *
 * This function will loop through all of the withheld frames in a pending ARP request and will forward 
 * each frame. The function will then delete the pending request, free the pending request, and return CHIROUTER_OK.
 *
 * ctx: Router context
 *
 * pending_req: The pending ARP request
 *
 * dest_mac: The destination MAC address
 *
 * Returns:
 *   CHIROUTER_OK (0) on success
 */
int chirouter_send_withheld(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req, uint8_t *dest_mac)
{
    /* Setting the element and temp pointers */
    withheld_frame_t *elt, *tmp;

    /* Locking mutex and looping through the withheld frames */
    pthread_mutex_lock(&ctx->lock_arp);

    /* Looping through the withheld frames using uthash */
    DL_FOREACH_SAFE(pending_req->withheld_frames, elt, tmp) {
        /* Forwarding the withheld frame */
        chirouter_forward_ip_frame(ctx, elt->frame, dest_mac, pending_req->out_interface);
    }

    /* Freeing the pending request frames */
    chirouter_arp_pending_req_free_frames(pending_req);

    /* Deleting the pending request */
    DL_DELETE(ctx->pending_arp_reqs, pending_req);

    /* Freeing the pending request and unlocking the mutex */
    free(pending_req);
    pthread_mutex_unlock(&ctx->lock_arp);

    return CHIROUTER_OK;
}

/*
 * chirouter_handle_arp_frame - Processes an ARP frame
 *
 * This function will process an ARP frame and will check if it is an ARP request or an ARP reply. If it is an ARP request, 
 * it will check if the target IP address matches the incoming interface IP address and will send an ARP reply. 
 * If it is an ARP reply, the function will add the IP address and MAC address to the ARP cache and will check for any 
 * pending ARP requests. If there is a pending ARP request, the function will send the withheld frames. The function will 
 * return CHIROUTER_OK if the ARP frame was processed successfully and CHIROUTER_ERROR if there is an error adding to 
 * the ARP cache.
 *
 * ctx: Router context
 *
 * frame: The ethernet frame
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if there is a malloc failure
 */
int chirouter_handle_arp_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Creating the ARP packet from the frame */
    arp_packet_t *arp_packet = (arp_packet_t *)(frame->raw + sizeof(ethhdr_t));

    /* Check if it is an ARP request */
    if (ntohs(arp_packet->op) == ARP_OP_REQUEST) {
        if (arp_packet->tpa == frame->in_interface->ip.s_addr) {
            chirouter_send_arp_reply(ctx, frame->in_interface, arp_packet);
        }
    } else if (ntohs(arp_packet->op) == ARP_OP_REPLY) {
        /* Assigning the IP from the reply */
        struct in_addr *reply_ip = calloc(1, sizeof(struct in_addr));
        memcpy(&reply_ip->s_addr, &arp_packet->spa, IPV4_ADDR_LEN);

        /* Locking the ARP mutex */
        pthread_mutex_lock(&ctx->lock_arp);

        /* Adding the ARP cache entry */
        if (!chirouter_arp_cache_lookup(ctx, reply_ip)) {
            if (chirouter_arp_cache_add(ctx, reply_ip, arp_packet->sha) != 0) {
                pthread_mutex_unlock(&ctx->lock_arp);
                return CHIROUTER_ERROR;
            }
        }

        /* Unlocking the ARP mutex */
        pthread_mutex_unlock(&ctx->lock_arp);

        /* Checking for a pending ARP request */
        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_pending_arp_req_t *pending_req = chirouter_arp_pending_req_lookup(ctx, reply_ip);
        pthread_mutex_unlock(&ctx->lock_arp);
        free(reply_ip);

        /* If there is a pending request, send the withheld frames */
        if (pending_req) {
            chirouter_send_withheld(ctx, pending_req, arp_packet->sha);
        }
    }

    return CHIROUTER_OK;
}

/*
 * chirouter_verify_routing_table - Verifies the routing table
 *
 * This function will loop through the routing table and checks if the destination IP address
 * matches the routing table entry. If they match, the function will check if the mask is greater 
 * than the frame mask and updates the frame mask and index. The function will return the index of the 
 * routing table entry that matches the frame destination, otherwise -1.
 *
 * ctx: Router context
 *
 * frame: The ethernet frame
 *
 * Returns:
 *   The index of the routing table entry that matches the frame destination, otherwise -1
 */
int chirouter_verify_routing_table(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Creating the IP header from the frame */
    struct iphdr *ip_hdr = (struct iphdr *)(frame->raw + sizeof(ethhdr_t));

    /* Getting the destination IP address */
    uint32_t frame_destination = ntohl(ip_hdr->dst);

    /* Initializing the frame mask and index  */
    uint32_t frame_mask = 0;
    int index = -1;

    /* Looping through the routing table */
    for (int i = 0; i < ctx->num_rtable_entries; i++) {
        /* Getting the destination and mask from the routing table */
        uint32_t table_destination = ntohl((uint32_t)((ctx->routing_table[i]).dest.s_addr));
        uint32_t table_mask = ntohl((uint32_t)((ctx->routing_table[i]).mask.s_addr));

        /* Masking the frame destination */
        uint32_t masked_frame = frame_destination & table_mask;

        /* Checking to see if the masked frame matches the table destination */
        if (masked_frame == table_destination) {
            /* Checking if the table mask is greater than the frame mask */
            if (table_mask >= frame_mask) {
                frame_mask = table_mask;
                index = i;
            }
        }
    }

    return index;
}

/*
 * chirouter_create_pending_request - Creates a pending request
 *
 * This function will check if a pending request exists for the forwarding IP address IP address. If the pending request 
 * does not exist, the function will create a new pending request. Then, the function will add the frame to the 
 * pending request frames and return CHIROUTER_OK if the frame was added successfully and CHIROUTER_ERROR otherwise.
 *
 * ctx: Router context
 *
 * entry_iface: The interface to send the pending request to
 *
 * frame: The ethernet frame
 *
 * forward_ip_addr: The IP address to forward to
 *
 * Returns:
 *   CHIROUTER_OK (0) on success, CHIROUTER_ERROR (1) if there is an error from adding the frame
 */
int chirouter_create_pending_request(chirouter_ctx_t *ctx, chirouter_interface_t *entry_iface, ethernet_frame_t *frame, struct in_addr forward_ip_addr)
{
    /* Checking the pending requests */
    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_pending_arp_req_t *pending_req = chirouter_arp_pending_req_lookup(ctx, &forward_ip_addr);
    pthread_mutex_unlock(&ctx->lock_arp);

    /* If the pending request does not exist, create one */
    if (!pending_req) {
        pthread_mutex_lock(&ctx->lock_arp);
        pending_req = chirouter_arp_pending_req_add(ctx, &forward_ip_addr, entry_iface);
        pthread_mutex_unlock(&ctx->lock_arp);
    }

    /* In both cases now add the frame to the pending frames */
    pthread_mutex_lock(&ctx->lock_arp);
    int result = chirouter_arp_pending_req_add_frame(ctx, pending_req, frame);
    pthread_mutex_unlock(&ctx->lock_arp);

    return result == 0 ? CHIROUTER_OK : CHIROUTER_ERROR;
}

/*
 * chirouter_handle_routing_frame - Process a single routing frame
 *
 * This function will be called every time a frame needs to possibly be routed. It will 
 * look to see if there is a routing table match, and if so then it will deal with ARP 
 * requests and pending requests, and then eventually forwarding the frame. If the routing table
 * does not match then it will send a destination network unreachable message.
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   CHIROUTER_OK (0) on success
 */
int chirouter_handle_routing_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Getting the IP header from the frame */
    iphdr_t *ip_hdr = (iphdr_t *)(frame->raw + sizeof(ethhdr_t));

    /* Getting the destination IP address and creating in_addr struct */
    struct in_addr dest_ip_addr;
    memcpy(&dest_ip_addr, &ip_hdr->dst, IPV4_ADDR_LEN);

    /* Attempting to get the routing table index */
    int route_index = chirouter_verify_routing_table(ctx, frame);

    /* Checking to see if the routing table index exists */
    if (route_index >= 0) {
        if (ip_hdr->ttl == 1) {
            chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_TIME_EXCEEDED, 0, frame);
            return CHIROUTER_OK;
        }

        /* Accessing the actual table entry */
        chirouter_rtable_entry_t *entry = &ctx->routing_table[route_index];

        /* Getting the interface from the entry */
        chirouter_interface_t *entry_iface = entry->interface;

        /* Creating the IP address to forward to */
        struct in_addr forward_ip_addr;
        memcpy(&forward_ip_addr.s_addr, &dest_ip_addr.s_addr, IPV4_ADDR_LEN);

        /* Checking if the gateway address is not 0 */
        if(entry->gw.s_addr != 0) {
            memcpy(&forward_ip_addr.s_addr, &entry->gw.s_addr, IPV4_ADDR_LEN);
        }

        /* Locking the ARP cache and trying to find an ARP cache entry */
        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_arpcache_entry_t *cache_entry = chirouter_arp_cache_lookup(ctx, &dest_ip_addr);
        pthread_mutex_unlock(&ctx->lock_arp);

        /* Checking if there is no entry  */
        if (!cache_entry) {
            /* Sending an ARP request */
            chirouter_send_arp_request(ctx, entry_iface, &dest_ip_addr);

            /* Creating a new pending request */
            chirouter_create_pending_request(ctx, entry_iface, frame, forward_ip_addr);
        } else {
            /* Forwarding the IP frame */
            chirouter_forward_ip_frame(ctx, frame, cache_entry->mac, entry_iface);
        }
    } else {
        /* Sending network unreachable */
        chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_NET_UNREACHABLE, frame);
    }

    return CHIROUTER_OK;
}

/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Getting the ethernet header from the frame */
    ethhdr_t *ethhdr = (ethhdr_t *)frame->raw;

    /* Getting the type from the ethernet header */
    uint16_t eth_type = ntohs(ethhdr->type);

    /* ARP packet processing */
    if (eth_type == ETHERTYPE_ARP) {
        /* Going into the ARP handler */
        chirouter_handle_arp_frame(ctx, frame);
    }

    /* IP Packet Processing */
    else if (eth_type == ETHERTYPE_IP) {
        /* Creating the IP header from the frame and ethernet header size */
        iphdr_t *ip_hdr = (iphdr_t *)(frame->raw + sizeof(ethhdr_t));

        /* Checking to see if the IP header matches the incoming frame IP header */
        if (ip_hdr->dst == (uint32_t)frame->in_interface->ip.s_addr) {
            /* Checking the TTL */
            if (ip_hdr->proto == IPPROTO_TCP || ip_hdr->proto == IPPROTO_UDP) {
                /* Sending an ICMP destination port unreachable reply */
                chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_PORT_UNREACHABLE, frame);
            } else if (ip_hdr->ttl == 1) {
                /* Send ICMP time exceeded message */
                chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_TIME_EXCEEDED, 0, frame);
            } else if (ip_hdr->proto == IPPROTO_ICMP) {
                /* Creating the ICMP packet */
                icmp_packet_t *icmp_packet = (icmp_packet_t *)(frame->raw + sizeof(ethhdr_t) + ip_hdr->ihl * 4);

                /* Checking for an ECHO request */
                if (icmp_packet->type == ICMPTYPE_ECHO_REQUEST) {
                    /* ICMP echo request received, going to send an echo reply */
                    chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_ECHO_REPLY, 0, frame);
                }
            }
        } else if (!chirouter_check_interface(ctx, ip_hdr->dst)) {
            /* Sending a destination unreachable message */
            chirouter_send_icmp_reply(ctx, frame->in_interface, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_HOST_UNREACHABLE, frame);
        } else {
            /* Going into the routing handler */
            chirouter_handle_routing_frame(ctx, frame);
        }
    }

    return CHIROUTER_OK;
}