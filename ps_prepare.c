#include<stdio.h> 
#include<string.h>    
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>    
 
#include "ps_prepare.h"
#include "ps_setup.h"


//Prepare a TCP packet
char * prepare_tcp_pkt(char *dst_ip, int dst_port, char *src_ip, int src_port, int scan_type)
{
	struct iphdr *ip_header = NULL;	
	struct tcphdr *tcp_header = NULL;
	//Datagram to represent the packet
	char *datagram = (char*)malloc(4096);

	//IP header
	ip_header = (struct iphdr *) datagram;

	//TCP header
	tcp_header = (struct tcphdr *) (datagram + sizeof (struct ip));

	//struct sockaddr_in  dest;
	struct pseudo_header_tcp psh;



	memset (datagram, 0, 4096); /* zero out the buffer */

	//Fill in the IP Header
	ip_header->ihl = 5;
	ip_header->version = 4;
	ip_header->tos = 0;
	ip_header->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	ip_header->id = htons(9999); //to identify our packets easily on the wire in tcpdump
	ip_header->frag_off = htons(0);
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0;
	ip_header->saddr = inet_addr(src_ip);
	ip_header->daddr = inet_addr(dst_ip);
	//calculate the checksum of ip header
	ip_header->check = calculate_tcpcsum((uint16_t *) datagram, ip_header->tot_len >> 1);


	//TCP Header
	tcp_header->source = htons(src_port);
	tcp_header->dest = htons(dst_port);
	tcp_header->seq = htonl(9999999); //to identify our packets easily on the wire in tcpdump
	tcp_header->ack_seq = 0;
	tcp_header->doff = sizeof(struct tcphdr)/4;
	tcp_header->fin=0;
	tcp_header->syn=0;
	tcp_header->rst=0;
	tcp_header->psh=0;
	tcp_header->ack=0;
	tcp_header->urg=0;
	tcp_header->window = htons(14600);
	tcp_header->check = 0;
	tcp_header->urg_ptr = 0;


	switch(scan_type)
	{
	case SYN_SCAN:
		tcp_header->syn=1;
		break;
	case NULL_SCAN:
		break;
	case FIN_SCAN:
		tcp_header->fin=1;
		break;
	case XMAS_SCAN:
		tcp_header->fin=1;
		tcp_header->psh=1;
		tcp_header->urg=1;
		break;
	case ACK_SCAN:
		tcp_header->ack=1;  //this should be 1??
				break;
	}

	psh.source_address = inet_addr( src_ip );
	psh.dest_address = inet_addr ( dst_ip );
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons( sizeof(struct tcphdr) );

	memcpy(&psh.tcp , tcp_header , sizeof (struct tcphdr));

	//calculate the checksum of tcp header
	tcp_header->check = calculate_tcpcsum((uint16_t*)&psh ,sizeof(struct pseudo_header_tcp));

	return datagram;
}



//prepare a DNS query packet
char * prepare_dnsquery_pkt(unsigned char *host, int query_type, int *pktlen)
{
    unsigned char *qname;
	char *buf = (char*)malloc(4096);

 
    dns_header *dns = NULL;
    dns_query *query = NULL;
 
    //Set the DNS structure to standard queries
    dns = (struct DNS *)buf;
	memset (buf, 0, 4096);
 
    dns->id = htons(1234); //check this once 
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available
    dns->z = 0;
    //dns->ad = 0;
    //dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    //Copy the host name to be resolved
	qname =(unsigned char*)(buf + sizeof(struct DNS));
	strcpy((char *)qname,(char *)host);
	
	//printf("qname : %s\n",qname);
	
    //Add the query payload
    query =(struct question*)(buf + sizeof(struct DNS) + (strlen((const char*)qname) + 1)); 
 
    query->qtype = htons(query_type); //type of the query , A , MX , CNAME , NS etc
    query->qclass = htons(1); //internet
	
	*pktlen = sizeof(struct DNS) + (strlen((const char*)qname)+1) + sizeof(struct question);
 

   return buf;
  }
  


char * prepare_udp_pkt_with_payload()
{
	int i;
    char *buf = (char*)malloc(30);
	memset (buf, 0, 30);
	for(i=0;i<20;i++)
	{
		strcpy(buf,"a");
	
	}
	 return buf;
	 
   
 }
  


/*
 * Ref: http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
 * The checksum field is the 16 bit one's complement of the one's complement sum of all 16-bit words in the header and text.
 * If a segment contains an odd number of header and text octets to be checksummed, the last octet is padded on the right with
 * zeros to form a 16-bit word for checksum purposes. The pad is not transmitted as part of the segment. While computing the
 * checksum, the checksum field itself is replaced with zeros.
 * In other words, after appropriate padding, all 16-bit words are added using one's complement arithmetic. The sum is then
 * bitwise complemented and inserted as the checksum field.
 */

//used to calculate the tcp checksum and ip checksum...
unsigned short calculate_tcpcsum(uint16_t *ptr,int pktlen)
{
	uint32_t csum = 0;

	//add 2 bytes / 16 bits at a time!!
	while(pktlen>1) {
		csum += *ptr++;
		pktlen-=2;
	}

	//add the last byte if present
	if(pktlen==1) {
		csum += *(uint8_t *)ptr;
	}

	//add the carries
	csum = (csum>>16) + (csum & 0xffff);
	csum = csum + (csum>>16);

	//return the one's compliment of calculated sum
	return((short)~csum);
}




