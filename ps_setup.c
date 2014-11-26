/*
 * ps_setup.c
 *
 *  Created on: Nov 8, 2013
 *      Author: SriHariVardhan
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <endian.h>
#include <math.h>
#include "ps_setup.h"



ipAddress_t * ip_list_top = NULL;
port_t * port_list_top = NULL;
job_t * job_masterlist_top = NULL;
job_t * job_list_top = NULL;
result_t * result_masterlist_top = NULL;

int ip_list_count = 0;
int port_list_count = 0;
int job_masterlist_count = 0;
int job_list_count = 0;
int result_list_count = 0;
int scan[6];
int scan_mode = UNASSIGNED;
extern int no_of_threads;


/**********************************************************
 *  usage(FILE * file) -> void
 *
 *  print the usage of this program to the file stream file
 *
 **********************************************************/

void usage(FILE * file){
	if(file == NULL){
		file = stdout;
	}
	fprintf(file,
			"portScanner [OPTIONS]\n"
			"  --help        \t Print this help screen\n"
			"  --ports       \t ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"
			"  --ip 	   	 \t ip addresses to scan in dot format\n"
			"  --prefix      \t ip prefix to scan\n"
			"  --file        \t File name containing IP addresses to scan,\n"
			"  --speedup     \t number of parallel threads to use\n"
			"  --scan        \t SYN/NULL/FIN/XMAS/ACK/UDP \n");
}


/*
 *  _parse_args(int argc, char * argv[]) -> void
 *
 *   parse the command line arguments to bt_client using getopt and
 *   store the result in bt_args.
 *
 *   ERRORS: Will exit on various errors
 */
void parse_args(int argc, char * argv[])
{
	int ch;
	int option_index = 0;
	int i;
	char *word;
	int prefix = 0;
	struct hostent *targetIPAddress;
	static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"ports", 1, 0, 'p'},
			{"ip", 1, 0, 'i'},
			{"prefix", 1, 0, 'x'},
			{"file", 1, 0, 'f'},
			{"speedup", 1, 0, 't'},
			{"logfile", 1, 0, 'l'},
			{"verbose", 0, 0, 'v'},
			{"scan", 1, 0, 's'},
			{NULL, 0, NULL, 0}
	};

	char port_args[MAX_ARG_SIZE];
	char ip_args[MAX_ARG_SIZE];
	char prefix_args[MAX_ARG_SIZE];
	char scan_args[MAX_ARG_SIZE];
	char *ip;
	char sep[] = "/";

	//default value for ps_args->ports
	bzero(port_args,MAX_ARG_SIZE);
	strcpy(port_args,"1-1024");

	//default for ps_args->scan
	for(i=0;i<6;i++)
	{
		scan[i] = 1;
	}

	//default for no_of_threads
	no_of_threads = 0;

	while ((ch = getopt_long(argc, argv, "",long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'h':	printf("Help Screen\n");
					usage(stdout);
					exit(SUCCESS);
		case 'p': 	bzero(port_args,MAX_ARG_SIZE);
					strcpy(port_args,optarg);
					get_ports(port_args);
					break;
		case 'i':	strcpy(ip_args, optarg);
					//printf("IP address to scan is %s\n",ip_args);
					targetIPAddress = gethostbyname(ip_args);
					if(targetIPAddress != NULL)
					{
						push_ip(ip_args);
					}
					break;
		case 'x':	strcpy(prefix_args, optarg);
					//printf("IP Prefix to scan is %s\n",prefix_args);
					//only can have 2 tokens max, but may have less
					for(word = strtok(prefix_args, sep), i=0;
							(word && i < 3);
							word = strtok(NULL,sep), i++){

						switch(i){
						case 0://id
							ip = word;
							break;
						case 1://ip
							prefix = atoi(word);
						default:
							break;
						}
					}
					//call function to get the ip address list
					get_ipAdresses(ip,prefix);
					break;
		case 'f':	printf("Filename that contains IP addresses is %s\n",optarg);
					//strncpy(ps_args->filename,optarg,MAXLEN);
					//call function to get the ip address list from the file
					read_ipAddresses(optarg);
					break;
		case 't':	no_of_threads = atoi(optarg);
					break;
		case 'l':	//printf("logfile : %s\n",optarg);
					break;
		case 'v':	//printf("verbose mode enabled!!\n");
					break;
		case 's':	bzero(scan_args,MAX_ARG_SIZE);
					strcpy(scan_args,optarg);
					for(i=0;i<6;i++)
					{
						scan[i] = 0;
					}
					break;
		}

	}

	for (i = optind; i < argc; i++)
	{
		strcat(scan_args,";");
		strcat(scan_args,argv[i]);
	}


	if(port_list_top == NULL)
	{
		get_ports_range(port_args);
	}

	//strtok scan_args
	for(word = strtok(scan_args, ";"), i=0;
			(word && i < 7);
			word = strtok(NULL,";"), i++)
	{
		//printf("Word is %s\n",word);
		if (strcmp(word,"SYN") == 0)
			scan[0] = 1;
		else if (strcmp(word,"NULL") == 0)
			scan[1] = 1;
		else if (strcmp(word,"FIN") == 0)
			scan[2] = 1;
		else if (strcmp(word,"XMAS") == 0)
			scan[3] = 1;
		else if (strcmp(word,"ACK") == 0)
			scan[4] = 1;
		else if (strcmp(word,"UDP") == 0)
			scan[5] = 1;
	}

	/*printf("Scan Flags set are :\n");
				for(i=0;i<6;i++)
				{
						printf("scan[%d] = %d\n",i, scan[i]);
				}*/


	//print_ip();
	//print_port();
}



void get_ports(char * port_args)
{
	int count,index;
	char * word;
	char * word1;
	word = strtok(port_args,",");
	count = 1; index = 0;
	while(word != NULL)
	{

		if (strstr(word,"-") != NULL)
		{
			word1 = (char *)malloc(strlen(word)+1);
			strcpy(word1,word);
			//printf("word1 is %s\n",word1);
			get_ports_range(word1);
			//printf("portargs : %s",port_args);
			free(word1);

		}
		else
		{
			push_port(atoi(word));
		}
		word = strtok(NULL,",");

	}
}

void get_ports_range(char * word)
{
	int init_val,end_val;
	int i;
	char * pos;
	init_val = atoi(word);
	pos = strstr(word,"-");
	pos++;
	end_val = atoi(pos);

	for (i = init_val; i <= end_val; i++)
	{
		push_port(i);
	}

}

int get_hostcount(int prefix)
{
	if(prefix > 32)
	{
		printf("Provided IPAdress and prefix are not valid\n");
		exit(FAILURE);
	}
	return ((int)(pow(2,(double)(32 - prefix))) - 2);
}


int get_ipAdresses(char *ipAddress,int prefix)
{
	//ipAddress in dot format
	uint8_t ip[4]= {0,0,0,0};
	uint8_t netmask[4] = {255,255,255,255};
	uint8_t host[4] = {255,255,255,255};
	uint8_t new_ip[4]= {0,0,0,0};
	unsigned char mask = 0x01;
	unsigned char *word;
	int i = 0, bit = 0, byte = 0,hostcount = 0;
	uint32_t newip = 0;
	char newIPAddress[INET_ADDRSTRLEN];
	struct hostent *targetIPAddress;

	for(word = (unsigned char*)strtok(ipAddress, "."), i=0;	(word && i < 4); word = (unsigned char*)strtok(NULL,"."), i++){
		ip[i] = (uint8_t)atoi((char *)word);
		//printf("word : %s\n",word);
	}

	//find the number of hosts
	hostcount = get_hostcount(prefix);

	//find netmask
	for(i = (32 - prefix - 1); i >= 0; i--)
	{
		byte = (int)((32 - i) / 8);
		if(i == 0)
			byte--;
		else if((i > 0) & (i % 8 == 0))
		{
			byte -= (int)(i/8);
		}
		bit = i % 8;
		netmask[byte] = netmask[byte] & (~(mask << bit));
		//printf("bit : %d, netmask[%d] = %d\n",bit,byte,netmask[byte]);
	}

	//copy the network part of the address into a buffer
	for(i=0;i<4;i++)
	{
		host[i] = ip[i] & netmask[i];
		new_ip[i] = host[i];
	}

	//iterate through each host number and append it to network address to get the host ip
	for(i = 1; i <= hostcount; i++)
	{
		memcpy(&newip,host,sizeof(uint32_t));
		newip = htole32(newip);
		newip |= htobe32((uint32_t)i);
		memcpy(new_ip,&newip,sizeof(uint32_t));

		bzero(newIPAddress,INET_ADDRSTRLEN);
		sprintf(newIPAddress,"%d.%d.%d.%d",new_ip[0],new_ip[1],new_ip[2],new_ip[3]);

		targetIPAddress = gethostbyname(newIPAddress);
		if(targetIPAddress != NULL)
		{
			//printf("%d - %s\n",i,newIPAddress);
			push_ip(newIPAddress);
		}
		else
		{
			//printf("Host not found for ip address : %s\n",newIPAddress);
		}

		//print the first and the last ipAddress in the given ip-prefix range
		if(i == 1 || i == hostcount)
			printf("Host %d : %d.%d.%d.%d \n",i,new_ip[0],new_ip[1],new_ip[2],new_ip[3]);
	}

	printf("ipAddress : %d.%d.%d.%d ",ip[0],ip[1],ip[2],ip[3]);
	printf("SubnetMask : %d.%d.%d.%d and host count : %d\n",netmask[0],netmask[1],netmask[2],netmask[3],hostcount);
	//printf("Host : %d.%d.%d.%d \n",host[0],host[1],host[2],host[3]);

	return SUCCESS;

}

void create_jobs()
{
	ipAddress_t * ip_list = ip_list_top;
	port_t * port_list = port_list_top;
	int i = 0;

	for(i=0;i < 6;i++)
	{
		if(scan[i] == 0)
			continue;

		while(ip_list != NULL)
		{
			while(port_list != NULL)
			{
				//printf("Creating job : %s %d %d\n",ip_list->ip,port_list->portno,i);
				push_job(ip_list->ip,port_list->portno,i);
				port_list = port_list->next;
			}

			port_list = port_list_top;
			ip_list = ip_list->next;
		}
		ip_list = ip_list_top;
	}

	//check if the job list is populated...
	if(job_masterlist_top == NULL)
	{
		printf("Please check the usage...\n");
		usage(stdout);
		destroy_iplist();
		destroy_portlist();
		exit(FAILURE);
	}

}



int read_ipAddresses(char *filename)
{
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	struct hostent *targetIPAddress;

	fp = fopen(filename, "rb+");
	if (fp == NULL)
	{
		printf("Invalid file parsed!!...Ignoring the file");
		return FAILURE;
	}
	else
		fp = fopen(filename, "r");


	while ((read = getline(&line, &len, fp)) != -1) {
		//replace the newline character in the line!!
		line[strcspn(line,"\n")] = '\0';
		targetIPAddress = gethostbyname(line);
		if(targetIPAddress != NULL)
		{
			push_ip(line);
		}
		else
		{
			printf("line in file is not a valid ipAddress : %s\n",line);
		}

	}

	if (line)
		free(line);

	return SUCCESS;
}




void push_ip(char *data)
{
	struct hostent *remotehost;
	struct in_addr **addr_list;

	//first get the ip address and then store it in dotted format!!
	remotehost = gethostbyname(data);  //already checked for

	if ((remotehost) != NULL) {
		addr_list = (struct in_addr **)remotehost->h_addr_list;
	}
	else
	{//invalid ip
		return;
	}


	ipAddress_t *newnode = NULL;
	newnode = (ipAddress_t *)malloc(sizeof(ipAddress_t));

	//set the data
	//memcpy(newnode->ip,data,INET_ADDRSTRLEN);
	memcpy(newnode->ip,inet_ntoa(*addr_list[0]),INET_ADDRSTRLEN);
	newnode->next = ip_list_top;
	ip_list_top = newnode;
	ip_list_count++;
}


void push_port(int data)
{
	if(data > 1024 || data < 1) //allow only port range of 1-1024
		return;

	port_t *newnode = NULL;
	newnode = (port_t *)malloc(sizeof(port_t));

	//set the data
	newnode->portno = data;
	newnode->next = port_list_top;
	port_list_top = newnode;
	port_list_count++;
}


void push_job(char *data,int port,int scan)
{
	job_t *newnode = NULL;
	newnode = (job_t *)malloc(sizeof(job_t));

	//set the data
	memcpy(newnode->ip,data,INET_ADDRSTRLEN);
	newnode->portno = port;
	newnode->scan_type = scan;
	newnode->next = job_masterlist_top;
	job_masterlist_top = newnode;
	job_masterlist_count++;
}


void change_scan_mode(int scantype)
{
	if(scantype != NONE)
	{
		job_list_top = job_masterlist_top;
		job_list_count = job_masterlist_count;
	}
	scan_mode = scantype;

}


//changed job_masterlist_count <-> job_list_top
job_t *get_next_job()
{
	job_t *ret = NULL;

	if(job_masterlist_top == NULL)
	{
		return NULL;
	}

	ret = job_masterlist_top;
	job_masterlist_top = job_masterlist_top->next;
	job_masterlist_count--;
	return ret;

}



void destroy_iplist()
{
	ipAddress_t *node = NULL;
	ipAddress_t *prev_node = NULL;
	node = ip_list_top;
	ip_list_top = NULL;
	ip_list_count = 0;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}



void destroy_portlist()
{
	port_t *node = NULL;
	port_t *prev_node = NULL;
	node = port_list_top;
	port_list_top = NULL;
	port_list_count = 0;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}



void destroy_joblist(job_t *masterlist_top)
{
	job_t *node = NULL;
	job_t *prev_node = NULL;
	node = masterlist_top;
	job_masterlist_top = NULL;
	job_list_top = NULL;
	job_list_count = 0;
	job_masterlist_count = 0;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}




void print_ip()
{
	ipAddress_t *node = ip_list_top;

	while(node != NULL)
	{
		printf("ipAddress : %s\n",node->ip);
		node = node->next;
	}
}

void print_port()
{
	port_t *node = port_list_top;

	while(node != NULL)
	{
		printf("port : %d\n",node->portno);
		node = node->next;
	}
}


void print_results_dummy()
{
	result_t *node = result_masterlist_top;
	int ret = 0;

	while(node != NULL)
	{
		printf("IP   : %s\n",node->ip);
		printf("port : %d\n",node->portno);
		printf("Conclusion : %d ",node->conclusion);

		switch(node->conclusion)
		{
		case R_OPEN:
			ret += printf("%-15s","Open");
			break;
		case R_CLOSED:
			ret += printf("%-15s","Closed");
			break;
		case R_FILTERED:
			ret += printf("%-15s","Filtered");
			break;
		case R_OPN_FIL:
			ret += printf("%-15s","Open|Filtered");
			break;
		case R_UNFILTERED:
			ret += printf("%-15s","Unfiltered");
			break;
		}
		printf("\n");

		node = node->next;
	}
}


void print_jobs()
{
	job_t *node = job_masterlist_top;

	while(node != NULL)
	{
		printf("ipAddress : %s\n",node->ip);
		printf("port : %d\n",node->portno);
		node = node->next;
	}
}


//scan_type in the result field must be set before hand by the calling func
void push_result(result_t *result)
{
	int i = 0;
	result_t *temp_result = NULL;
	//result_t *prev_result = NULL;
	result_t *result_top = result_masterlist_top;


	while(result_top)
	{
		if((result_top->portno == result->portno) && (strcmp(result_top->ip,result->ip) == 0))
		{//already updated the result earlier
			break;
		}
		//prev_result = result_top;
		result_top = result_top->next;
	}

	if(result_top == NULL)
	{//if the result for this port-no and ip was never updated ... create new result_t and add it to the top

		//print_record(result);

		temp_result = (result_t *)malloc(sizeof(result_t));
		memcpy(temp_result->ip,result->ip,INET_ADDRSTRLEN);
		temp_result->portno = result->portno;
		memcpy(temp_result->service,result->service,MAX_SERVICE_NAME);
		for(i=0;i<6;i++)
			temp_result->result[i] = NONE; //set to default
		temp_result->conclusion = 10;
		temp_result->next = result_masterlist_top;
		result_masterlist_top = temp_result;
		result_list_count++;
		//printf("New : IP - %s | Prt - %d  | Srv - %s ",temp_result->ip,temp_result->portno,temp_result->service);
	}
	else
	{
		temp_result = result_top;
		//printf("Update : IP - %s | Prt - %d  | Srv - %s ",temp_result->ip,temp_result->portno,temp_result->service);
	}

	//update the new result
	temp_result->result[result->scan_type] = result->result[result->scan_type];

	//make a conclusion about the known results now
	//its the min value in the results array according to our implementation
#define MIN(a,b) a<b?a:b

	for(i=0;i<6;i++)
	{
		if(temp_result->result[i] != NONE)
		{
			temp_result->conclusion = MIN(temp_result->conclusion,temp_result->result[i]);
		}

	}

	//printf("New : IP - %s | Prt - %d  | Srv - %s ",temp_result->ip,temp_result->portno,temp_result->service);
	//printf(" Conclusion : %d --- ScanTyp - %d\n",temp_result->conclusion,result->scan_type);
	//free the earlier malloc'ed result structure
	free(result);
}




int x = 0;
#define PRINT_N(a,n) for(x=0;x<n;x++)printf(a);


void print_record(result_t *result)
{
	/**
	 * 		|	10 chars	|		30 chars		|		60 chars	| 20 chars	|
	 * 		|	port		|		SrvName			|		Results		| Conclusn	|
	 *
	 */

	int ret = 0, i =0;
	//first print the port
	printf("%-10d",result->portno);
	//now print the Service name
	printf("%-30.30s",result->service);

	for(i=0;i<=5;i++)
	{
		switch(i)
		{
		case SYN_SCAN:
			if(result->result[i] != NONE)
				ret += printf("SYN");
			break;
		case NULL_SCAN:
			if(result->result[i] != NONE)
				ret += printf("NULL");
			break;
		case FIN_SCAN:
			if(result->result[i] != NONE)
				ret += printf("FIN");
			break;
		case XMAS_SCAN:
			if(result->result[i] != NONE)
				ret += printf("XMAS");
			break;
		case ACK_SCAN:
			if(result->result[i] != NONE)
				ret += printf("ACK");
			break;
		case UDP_SCAN:
			if(result->result[i] != NONE)
				ret += printf("UDP");
			break;
		}

		switch(result->result[i])
		{
		case R_OPEN:
			ret += printf("(Open) ");
			break;
		case R_CLOSED:
			ret += printf("(Closed) ");
			break;
		case R_FILTERED:
			ret += printf("(Filtered) ");
			break;
		case R_OPN_FIL:
			ret += printf("(Open|Filtered) ");
			break;
		case R_UNFILTERED:
			ret += printf("(Unfiltered) ");
			break;
		}

		if(ret >= 50)
		{//print in new line....leave 40 chars in front
			printf("\n%40s"," ");
			ret = 0;
		}
	}

	//give spaces untill we reach conclusion column
	//printf("%?s",50 - ret," ");

	PRINT_N(" ",60-ret);



	switch(result->conclusion)
	{
	case R_OPEN:
		ret += printf("%-15s","Open");
		break;
	case R_CLOSED:
		ret += printf("%-15s","Closed");
		break;
	case R_FILTERED:
		ret += printf("%-15s","Filtered");
		break;
	case R_OPN_FIL:
		ret += printf("%-15s","Open|Filtered");
		break;
	case R_UNFILTERED:
		ret += printf("%-15s","Unfiltered");
		break;
	}

	printf("\n");

}


void print_results()
{

	//iterate through ip structures
	//for each ip first print all the open ports and clear the printed records.. then move to other conclusions
	int i = 0, printhdr_opn = TRUE,printhdr_cld = TRUE;
	ipAddress_t *ip_iterator = NULL;
	port_t *prt_iterator = NULL;
	result_t *rt_iterator = NULL;
	//result_t *prev_result = NULL;

	//print_results_dummy();

	ip_iterator = ip_list_top;
	while(ip_iterator != NULL)
	{//iterate through each ip
		printf("IP address: %s\n",ip_iterator->ip);
		printhdr_opn = TRUE;
		printhdr_cld = TRUE;
		for(i=0;i<=5;i++)//for each result type
		{

			prt_iterator = port_list_top;
			while(prt_iterator != NULL)
			{
				rt_iterator = result_masterlist_top;
				//prev_result = rt_iterator;
				while(rt_iterator != NULL)
				{//when ip matches with result record...check for the conclusion state first.
					if((strcmp(ip_iterator->ip,rt_iterator->ip) == 0) && (rt_iterator->conclusion == i) && (rt_iterator->portno == prt_iterator->portno))
					{
						//open closed filtered unfiltered and opn_filtered results
						if(i == R_OPEN && printhdr_opn)
						{
							printf("Open ports:\n");
							printf("%-10s%-30s%-60s%-20s\n","Port","Service Name (if applicable)","Results","Conclusion");
							PRINT_N("-",120);printf("\n");
							printhdr_opn = FALSE;

						}
						else if(i != R_OPEN && printhdr_cld)
						{
							printf("\nClosed/Filtered/Unfiltered ports:\n");
							printf("%-10s%-30s%-60s%-20s\n","Port","Service Name (if applicable)","Results","Conclusion");
							PRINT_N("-",120);printf("\n");
							printhdr_cld = FALSE;
						}

						print_record(rt_iterator);
						//check here for seg fault -- what if the match occurs on the top node
						/*prev_result->next = rt_iterator->next;
						free(rt_iterator);
						rt_iterator = prev_result->next;*/
					}
					//prev_result = rt_iterator;
					rt_iterator = rt_iterator->next;
				}//end of result iterator
				prt_iterator = prt_iterator->next;
			}//end of port iterator

		}//end of for loop
		ip_iterator = ip_iterator->next;
		printf("\n");
	}//end of ip iterator



}




void destroy_results()
{
	result_t *node = NULL;
	result_t *prev_node = NULL;
	node = result_masterlist_top;
	result_masterlist_top = NULL;
	result_list_count = 0;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}



//print configuration
void print_configurations()
{
	int i = 0;
	//No of valid ip address, No of ports, No of jobs to be scanned, Scan types...
	printf("Scan Configurations\n");

	if(ip_list_count == 1)
	{
		printf("Target Ip-Address          : %s\n",ip_list_top->ip);
	}
	else
	{
		printf("No of Ip-Addresses to scan : %d\n",ip_list_count);
	}


		printf("No of Ports to scan        : %d\n",port_list_count);

		printf("Scans to be performed      : ");

	for(i=0;i<=5;i++)
		{
			switch(i)
			{
			case SYN_SCAN:
				if(scan[i])
					printf("SYN ");
				break;
			case NULL_SCAN:
				if(scan[i])
					printf("NULL ");
				break;
			case FIN_SCAN:
				if(scan[i])
					printf("FIN ");
				break;
			case XMAS_SCAN:
				if(scan[i])
					printf("XMAS ");
				break;
			case ACK_SCAN:
				if(scan[i])
					printf("ACK ");
				break;
			case UDP_SCAN:
				if(scan[i])
					printf("UDP");
				break;
			}

			fflush(stdout);
		}
	printf("\n");

	if(no_of_threads != 0)
	{
		printf("No of threads              : %d\n",(no_of_threads > MAX_THREADS ? MAX_THREADS : no_of_threads));
	}
}
