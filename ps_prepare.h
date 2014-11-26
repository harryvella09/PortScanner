#include<netinet/tcp.h>
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/udp.h>
#include <netinet/ip_icmp.h>

#define TYPE_A 1 //Ipv4 address

#define DNS_PORT 53

//Function Prototypes
char * prepare_dnsquery_pkt(unsigned char *host, int query_type, int *pktlen);
char * prepare_udp_pkt_with_payload();
char * prepare_tcp_pkt(char *dst_ip, int dst_port, char *src_ip, int src_port, int scan_type);
//char * prepare_udp_pkt(char *dst_ip, int dst_port, char *src_ip, int src_port);
unsigned short calculate_tcpcsum(uint16_t *ptr,int pktlen);


struct pseudo_header_tcp    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};
 
//DNS header structure
typedef struct DNS
{
    unsigned short id; // identification number
	
	unsigned char qr :1; // query/response flag
	
	unsigned char opcode :4; // purpose of message
	
	unsigned char aa :1; // authoritative answer
	unsigned char tc :1; // truncation flag
    unsigned char rd :1; // recursion desired
    unsigned char ra :1; // recursion available
    
    unsigned char z :1; // its z! reserved
 
    unsigned char rcode :4; // response code
    
	//unsigned char cd :1; // checking disabled
    //unsigned char ad :1; // authenticated data
    
    unsigned short q_count; // Questions
    unsigned short ans_count; // Answer RRs
    unsigned short auth_count; // Authority RRs
    unsigned short add_count; // Additional RRs
}dns_header;
 
//Constant sized fields of query structure
typedef struct question
{
    unsigned short qtype;
    unsigned short qclass;
}dns_query;


