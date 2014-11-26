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
#include <fcntl.h>



typedef struct service_version{
	char ip[INET_ADDRSTRLEN];
	char version[6][50];
	struct service_version *next;
}servver_result_t;


int version_detection(int portno, char * dest_ip);
int recvData(int sockfd, char *data, int bytesToRead);
int sendHttpQuery(const char * filename,int sockfd);
void print_servver_result();
void push_servver_result(servver_result_t *result, int index);
int isversion_needed(int portno,char *ip);
servver_result_t *prepare_servversion_rslt(char *ip);
void destroy_servver_results();
int sendData(int sockfd, char *data, int dataLen);

#define EXIT_FAILURE 1
#define FAILURE 1
#define SUCCESS 0
#define BUF_LEN 1024
#define TRUE 1
#define FALSE 0

#define SSH 0
#define SMTP 1
#define WHOIS 2
#define HTTP 3
#define	POP 4
#define IMAP 5


//int result_list_count = 0;

