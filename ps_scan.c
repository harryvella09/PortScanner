/*
 * ps_scan.c
 *
 *  Created on: Nov 13, 2013
 *      Author: SriHariVardhan
 */


#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h> //hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/udp.h>
#include<pcap/pcap.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>

#include "ps_setup.h"
#include "ps_scan.h"
#include "ps_version.h"
#include "ps_prepare.h"


#define MIN_IP_HEADER_LEN 20
#define TIME_OUT 4
#define MAX_RETRY_COUNT 3
#define MAX_RECEIVE_BUFFER 1024


#define EXIT_FAILURE 1
#define SIZE_ETHERNET 14
//#define IP_HL(ip) (((ip)->vhl) & 0x0f)
//#define TCP_HL(tcp) (((th)->th_offx2 & 0xf0) >> 4)
#define PORT_NO 12345
#define DEFAULT_S_TIMEOUT 5
#define BUF_LEN 1024
#define SUCCESS 0



/*unsigned short csum(unsigned short *ptr,int nbytes);
char * prepare_tcp_pkt(char *dst_ip, int dst_port, char *src_ip, int src_port, int scan_type);
char * prepare_udp_pkt(char *dst_ip, int dst_port, char *src_ip, int src_port);
*/

result_t *prepare_rslt(char *ip,int portno, int scn_mode);
int get_timediff(struct timeval start);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
pcap_t * prepare_sniffing_session(int portno, int read_timeout);





/*
struct pseudo_header_tcp    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

struct pseudo_header_udp  //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short udp_length;

	struct udphdr udp;
};
*/
pcap_t * session;

extern int scan[6];
extern ipAddress_t * ip_list_top;
extern port_t * port_list_top;
extern job_t * job_masterlist_top;
extern job_t * job_list_top;
extern result_t * result_masterlist_top;
extern int scan_mode;
extern int no_of_threads;
extern char localip[INET_ADDRSTRLEN];

extern pthread_mutex_t threadlock;
extern pthread_cond_t  dataPresentCondition;
extern pthread_mutex_t lock[MAX_THREADS];


void ps_default()
{
	job_t *currentjob = NULL;
	char *packet = NULL;
	result_t *current_result = NULL;
	int one = 1;
	const int *val = &one;
	int pktlen = 0;

	int sockfd = -1;
	struct sockaddr_in sin;
	//pcap variables
	int retval;
	struct sigaction act;

	//for tracking the retrys
	int count = 0;

	//alarm variables
	int s_timeout = TIME_OUT;
	act.sa_handler = sigfunc;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;  

	struct iphdr *ip_header = NULL;	

	//prepare a pcap session
	session = prepare_sniffing_session(PORT_NO,0); //listen continuously alarm will break the loop

	while(TRUE)
	{
		//reset retry conter
		count = 0;

		//get the next job in queue
		currentjob = get_next_job();

		//base condition
		if (currentjob == NULL) break;

		//printf("Current job : ip - %s port - %d scan mode - %d \n",currentjob->ip,currentjob->portno,currentjob->scan_type);

		//prepare the sin structure with job details
		sin.sin_family = AF_INET; 
		inet_pton(AF_INET, currentjob->ip, &sin.sin_addr);
		sin.sin_port = htons(currentjob->portno);

		//prepare appropreate packet
		if (currentjob->scan_type != UDP_SCAN)
		{

			packet = prepare_tcp_pkt(currentjob->ip, currentjob->portno,localip,PORT_NO,currentjob->scan_type);
			//create raw socket and send the packet...

			if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
				perror("sock:");
				exit(EXIT_FAILURE);
			}
		}
		else if(currentjob->scan_type == UDP_SCAN && currentjob->portno == DNS_PORT)
		{
			packet = prepare_dnsquery_pkt((unsigned char *)"www.google.com",TYPE_A,&pktlen);
			
			//create UDP socket and send the packet...
			if ((sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
				perror("sock:");
				exit(EXIT_FAILURE);
			}
		}
		else 
		{
			//prepare packet with out payload
			/*packet = prepare_udp_pkt(currentjob->ip, currentjob->portno,"129.79.247.86",PORT_NO);
			//create raw socket and send the packet...
			if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
				perror("sock:");
				exit(EXIT_FAILURE);
			}
			*/
			
			//prepare a packet with payload
			packet = prepare_udp_pkt_with_payload();
			//create UDP socket and send the packet...
			if ((sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
				perror("sock:");
				exit(EXIT_FAILURE);
			}
		}

		//set the ip header
		ip_header = (struct iphdr *)packet;
	
		//set the other parameters for the socket
		if (currentjob->scan_type != UDP_SCAN )
		{

			if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
				fprintf(stderr, "Warning: Cannot set HDRINCL for ip %s port %d\n",currentjob->ip, currentjob->portno);

			pktlen = ip_header->tot_len;

		}
		else if(currentjob->scan_type == UDP_SCAN)
		{
			//IP-header will be included as UDP_SCAN is not using a raw socket
			pktlen = 20;
		}
		
		do{

			if (sendto(sockfd, packet, pktlen, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
				fprintf(stderr, "Error sending datagram for ip %s port %d\n", currentjob->ip, currentjob->portno);
				break;
			}

			//Set the alarm
			sigaction (SIGALRM, &act, 0);
			alarm(s_timeout);

			//call got packet procedure on receipt of a single packet
			retval = pcap_dispatch(session,1, got_packet, (u_char *)currentjob);

			//switch off the alarm
			alarm(0);

			//if timeout has happened....deal with it
			if (retval == -2)
			{
				//increment the retry count
				count++;

				if(count == MAX_RETRY_COUNT)
				{
					current_result = prepare_rslt(currentjob->ip,currentjob->portno,currentjob->scan_type);
					current_result->scan_type = currentjob->scan_type;
				}


				//printf("Timeout happened and no response recorded\n");
				if (currentjob->scan_type == (NULL_SCAN) || currentjob->scan_type == (FIN_SCAN) || currentjob->scan_type == (XMAS_SCAN) || currentjob->scan_type == (UDP_SCAN))
				{
					if(count == MAX_RETRY_COUNT)
					{
						current_result->result[currentjob->scan_type] = R_OPN_FIL;
					}
					//printf("Result - Port Open/Filtered\n");//port open/filtered
				}
				if (currentjob->scan_type == (SYN_SCAN) || currentjob->scan_type == (ACK_SCAN))
				{
					if(count == MAX_RETRY_COUNT)
						current_result->result[currentjob->scan_type] = R_FILTERED;
					//printf("Result - Port Filtered\n"); //PORT FILTERED
				}

				if(count == MAX_RETRY_COUNT)
				{
					push_result(current_result);
				}


			}
			else
			{break;}
		}while (count < MAX_RETRY_COUNT);

		//clear the resources taken
		close(sockfd);
		free(packet);

		//do version detection if the current job is on a port which requires version detection
		if(currentjob->portno == 22 || currentjob->portno == 24 || currentjob->portno == 43 || currentjob->portno == 80 || currentjob->portno == 110 || currentjob->portno == 143)
		{
			if(isversion_needed(currentjob->portno,currentjob->ip) == TRUE)
			{
				version_detection(currentjob->portno,currentjob->ip);
			}
		}

	}



	//printf("Bye!!\n");
	//exit sequence
	pcap_close(session);

	return;

}




result_t *prepare_rslt(char *ip,int portno, int scn_mode)
{
	int i = 0;
	struct servent *service;
	result_t *temp_result = NULL;

	temp_result = (result_t *)malloc(sizeof(result_t));
	memcpy(temp_result->ip,ip,INET_ADDRSTRLEN);
	temp_result->portno = portno;

	if(scn_mode == UDP_SCAN)
		service = getservbyport(htons(portno), "udp");
	else
		service = getservbyport(htons(portno), "tcp");

	if (service != NULL)
	{
		strncpy(temp_result->service,service->s_name,MAX_SERVICE_NAME);
		//printf("Possible service : %s port - %d htons(portno) - %d\n",service->s_name,portno,htons(portno));
	}
	else
	{
		strncpy(temp_result->service,"Unassigned",MAX_SERVICE_NAME);
		//printf("Possible service : Unassigned, port - %d htons(portno) - %d\n",portno,htons(portno));
	}


	for(i=0;i<6;i++)
		temp_result->result[i] = NONE; //set to default
	temp_result->conclusion = NONE;
	temp_result->next = NULL;

	return temp_result;

}



// ref : http://www.linuxquestions.org/questions/programming-9/how-to-calculate-time-difference-in-milliseconds-in-c-c-711096/
long long timeval_diff(struct timeval *difference,struct timeval *end_time,struct timeval *start_time)
{
	struct timeval temp_diff;

	if(difference==NULL)
	{
		difference=&temp_diff;
	}

	difference->tv_sec =end_time->tv_sec -start_time->tv_sec ;
	difference->tv_usec=end_time->tv_usec-start_time->tv_usec;

	while(difference->tv_usec<0)
	{
		difference->tv_usec+=1000000;
		difference->tv_sec -=1;
	}

	return 1000000LL*difference->tv_sec+
			difference->tv_usec;

}




#define ERROR 10
#define RETRY 11
#define GOT_PKT 12

void ps_threaded(void * thread_args)
{

	job_t * currentjob = NULL;
	int thread_id =  *((int *)thread_args);
	struct iphdr *ip_header = NULL;	


	char *packet = NULL;
	int action;

	int one = 1;
	const int *val = &one;

	int sockfd = -1;
	int recv_sockfd = -1;
	int recv_sockfd_icmp = -1;
	struct sockaddr_in source;
	struct sockaddr_in dest;
	int pktlen = 0;

	int thread_portno = PORT_NO + thread_id;

	char *recvbuffer = NULL;
	struct timeval start;
	struct timezone tz;
	int ms_timeout = 0; 
	int retry = 0;
	struct sockaddr saddr;
	socklen_t saddr_size = sizeof saddr;
	struct iphdr *iph;
	uint8_t src[4];
	char *incoming_ip;
	struct tcphdr *tcph= NULL;
	struct udphdr *udph= NULL;
	struct icmphdr *icmph = NULL;
	result_t *current_result = NULL;
	
	struct pollfd my_pollfds[2];
	int rv,retval;

	while (TRUE)
	{
		if (pthread_mutex_lock(&threadlock)) {
			perror("pthread_mutex_lock ");
			exit(1);
		}

		//get next job
		currentjob = get_next_job();
		//reset the retry counter
		retry = 0;


		if (pthread_mutex_unlock(&threadlock)) {
			perror("pthread_mutex_lock");
			exit(1);
		}

		if(currentjob == NULL)
		{
			//printf("Thread %d : All jobs done...exiting\n",thread_id);
			break;
		}


		//printf("Thread %d : current job : ip - %s port no - %d scan_mode - %d\n",thread_id, currentjob->ip, currentjob->portno,currentjob->scan_type);

		do{

			if (currentjob->scan_type != UDP_SCAN)
			{
				packet = prepare_tcp_pkt(currentjob->ip, currentjob->portno,localip,thread_portno,currentjob->scan_type);
				//create raw socket to send the packet...
				if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

				//create raw socket to recv the packet...
				if ((recv_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

			}

			else if(currentjob->scan_type == UDP_SCAN && currentjob->portno == DNS_PORT)
			{
				packet = prepare_dnsquery_pkt((unsigned char *)"www.google.com",TYPE_A,&pktlen);

				//create UDP socket and send the packet...
				if ((sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

				if ((recv_sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

			}
			else
			{
				//prepare a packet with payload
				packet = prepare_udp_pkt_with_payload();
				//create UDP socket and send the packet...
				if ((sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

				if ((recv_sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP)) < 0) {
					perror("sock:");
					exit(EXIT_FAILURE);
				}

			}
			//create an icmp receiving socket
			if ((recv_sockfd_icmp = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP)) < 0) {
					perror("receving icmp sock:");
					exit(EXIT_FAILURE);
				}


			memset((void*)&source, 0, sizeof(source));
			memset((void*)&dest, 0, sizeof(dest));

			source.sin_family = AF_INET;
			dest.sin_family = AF_INET;

			source.sin_addr.s_addr = inet_addr(localip);
			inet_pton(AF_INET, currentjob->ip, &dest.sin_addr);

			source.sin_port = htons(thread_portno);
			dest.sin_port = htons(currentjob->portno);

			//set the ip_header
			ip_header = (struct iphdr *)packet;

			if (currentjob->scan_type != UDP_SCAN )
			{
				if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
					fprintf(stderr, "Warning: Cannot set HDRINCL for ip %s port %d\n",currentjob->ip, currentjob->portno);

				if (setsockopt(recv_sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
					fprintf(stderr, "Warning: Cannot set HDRINCL for recvsock ip %s port %d\n",currentjob->ip, currentjob->portno);

				pktlen = ip_header->tot_len;

			}
			else if(currentjob->scan_type == UDP_SCAN && currentjob->portno != DNS_PORT)
			{
				pktlen = 20;
			}
			
			//bind for udp/tcp packets
			retval = bind(recv_sockfd, (struct sockaddr*)&source, sizeof(source));
			if( retval != 0){
				perror("Bind Failed: ");
				exit(EXIT_FAILURE);
			}
			//poll for events
			my_pollfds[0].fd = recv_sockfd;
			my_pollfds[0].events = POLLIN; // check for normal

			my_pollfds[1].fd = recv_sockfd_icmp;
			my_pollfds[1].events = POLLIN; // check for just normal data

			//start the timer
			(void) gettimeofday (&start, &tz);
			//set default time out to 4 seconds
			ms_timeout = 4000;
			
			if (sendto(sockfd, packet, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
				fprintf(stderr, "Error sending datagram for ip %s port %d -- errno %d\n", currentjob->ip, currentjob->portno,errno);
				perror("SendTo-error : ");
			}
			
			recvbuffer = (char *)malloc(MAX_RECEIVE_BUFFER);

			//continue reading till we receive the correct packet..or time out occurs..
			while(TRUE)
			{
				bzero(recvbuffer,MAX_RECEIVE_BUFFER);
				
				// wait for events on the sockets, 4 second timeout
				rv = poll(my_pollfds, 2, ms_timeout);
				if (rv == -1) {
					perror("poll"); // error occurred in poll()
					//set action to RETRY and break
					action = RETRY;
					break;
				} else if (rv == 0) {
					//printf("Thread %d : Timeout occurred!  No data after %d seconds.\n",thread_id,get_timediff(start));
					//set retry
					action = RETRY;
					break;
				} else {
					// check for events on s1:
					if (my_pollfds[0].revents & POLLIN)
					{
							retval = recvfrom(recv_sockfd, recvbuffer, MAX_RECEIVE_BUFFER, 0,&saddr , &saddr_size);
							//printf("Received UDP/TCP Packet\n");
							iph = (struct iphdr*)(recvbuffer);

						if ((int)((iph->ihl) * 4) < MIN_IP_HEADER_LEN) { //check for zero size sized packets and incomplete packets....discard them and proceed!!
							printf("Invalid IP header length: %u bytes\n", (int)((iph->ihl) * 4));
							if((ms_timeout -= get_timediff(start)) < 4000)
								continue; //continue reading the sockets
							else 
							{
								action = RETRY;
								break;
							}
						}
						if(iph->protocol == 6)
						{
							//check the tcp header data
							tcph=(struct tcphdr*)(recvbuffer + (int)((iph->ihl) * 4));

							memcpy(&src,&iph->saddr,4);
							//printf("Thread# %d : Time elapsed : %f, iph_protocol : %d, ip - %d.%d.%d.%d port : %d\n",thread_id, time_elapsed,iph->protocol, src[0],src[1],src[2],src[3],ntohs(tcph->source));

							incoming_ip = (char *)malloc(INET_ADDRSTRLEN);
							bzero(incoming_ip,INET_ADDRSTRLEN);
							sprintf(incoming_ip,"%d.%d.%d.%d",src[0],src[1],src[2],src[3]);

							//check if we have got the packet we are expecting
							if((strcmp(incoming_ip,currentjob->ip) == 0) && (ntohs(tcph->source) == currentjob->portno) && (ntohs(tcph->dest) == thread_portno))
							{//we have got the packet that we are waiting for... break & process the packet
								action = GOT_PKT;
								free(incoming_ip);
								break;
							}
							else 
							{
								if((ms_timeout -= get_timediff(start)) < 4000)
									{
										printf("Thread %d : received wrong packet!!...retry poll again!!\n",thread_id);
										free(incoming_ip);
										continue; //continue reading the sockets
									}
								else 
								{
									action = RETRY;
									free(incoming_ip);
									break;
								}
							}
						
						}
						if(iph->protocol == 17)
						{
							//check the tcp header data
							udph=(struct udphdr*)(recvbuffer + (int)((iph->ihl) * 4));

							memcpy(&src,&iph->saddr,4);
							//printf("Thread# %d : Time elapsed : %f, iph_protocol : %d, ip - %d.%d.%d.%d port : %d\n",thread_id, time_elapsed,iph->protocol, src[0],src[1],src[2],src[3],ntohs(tcph->source));

							incoming_ip = (char *)malloc(INET_ADDRSTRLEN);
							bzero(incoming_ip,INET_ADDRSTRLEN);
							sprintf(incoming_ip,"%d.%d.%d.%d",src[0],src[1],src[2],src[3]);

							//check if we have got the packet we are expecting
							if((strcmp(incoming_ip,currentjob->ip) == 0) && (ntohs(udph->source) == currentjob->portno) && (ntohs(udph->dest) == thread_portno))
							{//we have got the packet that we are waiting for... break & process the packet
								action = GOT_PKT;
								break;
							}
							else
							{
								if((ms_timeout -= get_timediff(start)) < 4000)
									continue; //continue reading the sockets
								else 
								{
									action = RETRY;
									break;
								}
							}
						
						}
						
					}
					
					//check for events on ICMP Socket
					if (my_pollfds[1].revents & POLLIN) {
						retval = recvfrom(recv_sockfd_icmp, recvbuffer, MAX_RECEIVE_BUFFER, 0,&saddr , &saddr_size);
						//printf("Received ICMP packet\n");
						iph = (struct iphdr*)(recvbuffer);
						icmph = (struct icmphdr*) (recvbuffer + (int)((iph->ihl) * 4));
						memcpy(&src,&iph->saddr,4);
						incoming_ip = (char *)malloc(INET_ADDRSTRLEN);
						bzero(incoming_ip,INET_ADDRSTRLEN);
						sprintf(incoming_ip,"%d.%d.%d.%d",src[0],src[1],src[2],src[3]);
										
						if((icmph->type != 3) || (strcmp(incoming_ip,currentjob->ip) != 0))
						{
							if((ms_timeout -= get_timediff(start)) < 4000)
								{
									free(incoming_ip);
									continue; //continue reading the sockets
								}
								else 
								{
									action = RETRY;
									free(incoming_ip);
									break;
								}
						}
						free(incoming_ip);
						action = GOT_PKT;
						break;
					}
				}
					
			} //while(TRUE);
								
			if (action == RETRY)
			{

				if(retry < MAX_RETRY_COUNT)
				{//start afresh...send...recv...and process
					//printf("Thread %d : Timeout happened and no response recorded retrying to scan - retry %d\n",thread_id,retry);
					retry++;
					free(packet);
					free(recvbuffer);
					close(sockfd);
					close(recv_sockfd);
					close(recv_sockfd_icmp);
					continue;
				}

				//if no response has been recorded in MAX_RETRY_COUNTs, then call it!!
				current_result = prepare_rslt(currentjob->ip,currentjob->portno,currentjob->scan_type);
				current_result->scan_type = currentjob->scan_type;

				if (currentjob->scan_type == (NULL_SCAN) || currentjob->scan_type == (FIN_SCAN) || currentjob->scan_type == (XMAS_SCAN) || currentjob->scan_type == (UDP_SCAN))
				{
					//printf("Thread ID : %d Result - Port Open/Filtered\n",thread_id);//port open/filtered
					current_result->result[currentjob->scan_type] = R_OPN_FIL;
				}
				if (currentjob->scan_type == (SYN_SCAN) || currentjob->scan_type == (ACK_SCAN))
				{
					//printf("Thread ID : %d Result - Port Filtered\n",thread_id); //PORT FILTERED
					current_result->result[currentjob->scan_type] = R_FILTERED;
				}

				push_result(current_result);


			}
			else if(action == GOT_PKT)
			{
				//printf("bytesRead retval : %d\n",retval);
				//process packet and save the result
				got_packet((u_char *)currentjob,NULL,(u_char *)recvbuffer);
			}

			//proceed with version detection
			if(currentjob->portno == 22 || currentjob->portno == 24 || currentjob->portno == 43 || currentjob->portno == 80 || currentjob->portno == 110 || currentjob->portno == 143)
			{
				if(isversion_needed(currentjob->portno,currentjob->ip) == TRUE)
				{
					version_detection(currentjob->portno,currentjob->ip);
				}
			}

			/* cleanup */
			free(packet);
			free(recvbuffer);
			close(sockfd);
			close(recv_sockfd);
			close(recv_sockfd_icmp);
			break; // and get next job
		}while(TRUE); //loop continuously

	}


	//printf("Thread %d : Bye!!\n",thread_id);
	pthread_exit(NULL);

}



int get_timediff(struct timeval start)
{
	struct timeval elapsed,interval;
	struct timezone tz;
		
	//get present time
	(void) gettimeofday (&elapsed, &tz);

	timeval_diff(&interval,&elapsed,&start);
	return((int)(interval.tv_sec * 1000));// + (double)(interval.tv_usec / 1000.0);
}



void sigfunc(int signum) {       /* signal handler */

	printf(".");
	fflush(stdout);

	if(no_of_threads == 0)
	{
		pcap_breakloop(session);
	}
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct icmphdr *icmph;
	struct udphdr *udph;

	int iph_len;
	int tcph_len;
	char ipadd[INET_ADDRSTRLEN];
	int ethernet_size = 0;

	result_t *current_result = NULL;
	job_t *currentjob = (job_t *)args;
	//printf("Inside got_packet : Job %s %d %d\n",currentjob->ip,currentjob->portno,currentjob->scan_type);
	uint8_t src[4];

	if(header != NULL)
		ethernet_size = SIZE_ETHERNET;

	//Get the IP Header part of this packet , excluding the Ethernet header
	iph = (struct iphdr*)(packet + ethernet_size);
	iph_len = (iph->ihl) * 4;
	if (iph_len < MIN_IP_HEADER_LEN) {
		printf("Invalid IP header length: %u bytes\n", iph_len);
		return;
	}

	memcpy(&src,&iph->saddr,4);
	//printf("iph_protocol : %d, ip - %d.%d.%d.%d\n",iph->protocol, src[0],src[1],src[2],src[3]);
	
	//prepare result 
		sprintf(ipadd,"%s", currentjob->ip);
		
	
	
	
	switch (iph->protocol) //Check the Protocol
	{
	case 1:  //ICMP - ICMP Unreachable Error indicates Port Filtered
		//printf("ICMP packet\n");
		icmph = (struct icmphdr*) (packet + ethernet_size + iph_len);
		//printf("icmph->type %d\n",icmph->type);
		//printf("icmph->code %d\n",icmph->code);
		if (icmph->type == 3)
		{
			switch (icmph->code) {
			case 1:
			case 2:
			case 9:
			case 10:
			case 13: current_result = prepare_rslt(ipadd,currentjob->portno,currentjob->scan_type);
					current_result->scan_type = currentjob->scan_type;
					current_result->result[currentjob->scan_type] = R_FILTERED;
					push_result(current_result);
					//printf("Destination Unreachable - Port Filtered\n");
					break;
			case 3: if (currentjob->scan_type == UDP_SCAN)
					{
						current_result = prepare_rslt(ipadd,currentjob->portno,currentjob->scan_type);
						current_result->scan_type = currentjob->scan_type;
		
						current_result->result[currentjob->scan_type] = R_CLOSED;
						//printf("Port Closed for UDP Packet\n");
					}
					else
					{
						current_result = prepare_rslt(ipadd,currentjob->portno,currentjob->scan_type);
						current_result->scan_type = currentjob->scan_type;
						current_result->result[currentjob->scan_type] = R_OPN_FIL;
						//printf("Destination Unreachable - Port Opn Filtered\n");
					}
					push_result(current_result);
					break;
			}
		}			
		break;			

	case 6:  //TCP Protocol
		//know the scan mode, check which flag is set, update result
		//printf("TCP PACKET\n");
		tcph = (struct tcphdr*)(packet + ethernet_size + iph_len);
		tcph_len = tcph->doff * 4;

		if (tcph_len < 20) {
			printf("Invalid TCP header length: %u bytes\n", tcph->doff);
			return;
		}


		//sprintf(ipadd,"%s", args);
		//sprintf(ipadd,"%s", currentjob->ip);
		//current_result = prepare_rslt(ipadd,ntohs(tcph->source),scan_mode);
		//current_result->scan_type = scan_mode;
		current_result = prepare_rslt(ipadd,ntohs(tcph->source),currentjob->scan_type);
		current_result->scan_type = currentjob->scan_type;
		//printf("Preaparing result for %s and %d\n",ipadd,ntohs(tcph->source));


		if (((tcph->syn) == 1) && (tcph->ack) == 1) //SYN SCAN
		{
			current_result->result[currentjob->scan_type] = R_OPEN;
			//printf ("TCP port %d open \n",ntohs(tcph->source));
		}

		if ((tcph->rst) == 1)
		{
			if (currentjob->scan_type == ACK_SCAN)
			{
				current_result->result[currentjob->scan_type] = R_UNFILTERED;
				//printf ("TCP port %d unfiltered\n",ntohs(tcph->source));
			}
			else
			{
				current_result->result[currentjob->scan_type] = R_CLOSED;
				//printf("TCP Port Closed\n");
			}
		}

		push_result(current_result);
		break;

	case 17: //UDP Protocol
		udph = (struct udphdr*)(packet + ethernet_size + iph_len);
		//printf("Port is open for UDP Scan TYPE\n");
		//printf("Src prt : %d, Dst prt : %d, len : %d, Chksm : %d\n"
				//,ntohs(udph->source)
				//,ntohs(udph->dest)
				//,ntohs(udph->len)
				//,udph->check
		//);
		if(ntohs(udph->source) == currentjob->portno)
		{
			current_result = prepare_rslt(ipadd,currentjob->portno,currentjob->scan_type);
			current_result->scan_type = currentjob->scan_type;
			current_result->result[currentjob->scan_type] = R_OPEN;
			//printf("UDP PORT OPEN\n");
			push_result(current_result);
		}
		break;
	}



}



pcap_t * prepare_sniffing_session(int src_port, int read_timeout){

	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct in_addr addr;

	int snaplen = 1518; //maximum bytes to be captured
	int promisc = 0; //non promiscous mode

	bpf_u_int32 devip, netmask;
	char * ip;
	char * mask;

	//pcap_if_t *alldev, *device;

	struct bpf_program fp;		// compiled filter
	char filter_exp[50];      

	sprintf(filter_exp,"dst port %d or ip proto \\icmp",src_port); // filter the traffic based on src port

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		printf("Couldn't find default device: %s\n", errbuf);
		exit (EXIT_FAILURE);
	}
	//printf("Device is %s\n",dev);

	if (pcap_lookupnet(dev, &devip, &netmask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		devip = 0;
		netmask = 0;
	}
	addr.s_addr = devip;
	ip = inet_ntoa(addr);
	addr.s_addr = netmask;
	mask = inet_ntoa(addr);


	handle = pcap_open_live(dev,snaplen,promisc,read_timeout,errbuf);

	if (handle == NULL) {
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		exit (EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, netmask) == -1) {
		fprintf (stderr, "Couldn't parse filter %s: %s \n ", filter_exp, pcap_geterr(handle));
		exit (EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf (stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit (EXIT_FAILURE);
	}

	return handle;

}


