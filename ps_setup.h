/*
 * ps_setup.h
 *
 *  Created on: Nov 8, 2013
 *      Author: SriHariVardhan
 */

//#ifndef PS_SETUP_H_
//#define PS_SETUP_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>


#define MAXLEN 20
#define MAX_SERVICE_NAME 80

/*typedef struct portscanner_args{
	int no_of_threads;
	int scan[6];
}ps_args_t;
*/


typedef struct ipAddress_list{
	char ip[INET_ADDRSTRLEN];
	struct ipAddress_list *next;
} ipAddress_t;


typedef struct port_list{
	int portno;
	struct port_list *next;
} port_t;


typedef struct job_list{
	char ip[INET_ADDRSTRLEN];
	int portno;
	int scan_type;
	struct job_list *next;
} job_t;


#define R_OPEN 0
#define R_CLOSED 1
#define R_FILTERED 2
#define R_OPN_FIL 3
#define R_UNFILTERED 4


typedef struct result_list{
	char ip[INET_ADDRSTRLEN];
	char service[MAX_SERVICE_NAME];
	char result[6];
	int conclusion;
	int portno;
	int scan_type;
	struct result_list *next;
} result_t;




void parse_args(int argc,  char * argv[]);

//scan types
#define SYN_SCAN 0
#define NULL_SCAN 1
#define FIN_SCAN 2
#define XMAS_SCAN 3
#define ACK_SCAN 4
#define UDP_SCAN 5


#define SUCCESS 0
#define FAILURE 1
#define TRUE 1
#define FALSE 0


#define UNASSIGNED -1
#define NONE -2

#define MAX_ARG_SIZE 100
#define MAX_PORTS 1024
#define MAX_THREADS 25



void get_ports(char * port_args);
void get_ports_range(char * word);
int get_hostcount(int prefix);
int get_ipAdresses(char *ipAddress,int prefix);
int read_ipAddresses(char *filename);
void push_ip(char *data);
void usage(FILE * file);
void create_jobs();
void push_ip(char *data);
void push_port(int data);
void push_job(char *data,int port,int scan);
void change_scan_mode(int scantype);
job_t *get_next_job();
void destroy_iplist();
void destroy_portlist();
void destroy_joblist();
void print_ip();
void print_jobs();
void print_port();
void push_result(result_t *result);
void print_record(result_t *result);
void print_results();
void destroy_results();
void print_configurations();



//#endif /* PS_SETUP_H_ */
