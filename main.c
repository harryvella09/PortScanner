#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <ifaddrs.h>
#include "ps_setup.h"
#include "ps_scan.h"
#include "ps_version.h"

int find_localip();

int no_of_threads = 0;
char localip[INET_ADDRSTRLEN];

extern int scan[6];
extern ipAddress_t * ip_list_top;
extern port_t * port_list_top;
extern job_t * job_masterlist_top;
extern job_t * job_list_top;
extern result_t * result_masterlist_top;

pthread_mutex_t threadlock = PTHREAD_MUTEX_INITIALIZER;

void amAlive(int signum) {       /* signal handler */
	printf(".");
	fflush(stdout);
	alarm(1);
}



int main(int argc, char * argv[]){

	int i = 0,rc =0;
	pthread_t ps_thread[MAX_THREADS];
	int thread_id[MAX_THREADS];

	struct timeval start,elapsed,interval;
	struct timezone timezone;

	struct sigaction act;
	act.sa_handler = amAlive;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	job_t *temp_joblist_top = NULL;

	//parse args
	parse_args(argc, argv);

	if(ip_list_top == NULL)
	{
		printf("Please specify atleast one ipAddress to scan!!\n");
		usage(stdout);
		exit(FAILURE);
	}

	//Create a job list and print them
	create_jobs();

	//make a copy of the job list top -- to free the memory later!!
	temp_joblist_top = job_masterlist_top;

	//resolve the local ip
	find_localip();

	//print the configurations of the current instance
	print_configurations();

	printf("Scanning.."); fflush(stdout);
	sigaction (SIGALRM, &act, 0);
	alarm(1);

	//start the timer
	(void) gettimeofday (&start, &timezone);

	//Start the jobs
	if (no_of_threads == 0)
	{
		ps_default();
	}
	else
	{
		//cap the no_of_threads to MAX_THREADS
		no_of_threads = (no_of_threads > MAX_THREADS ? MAX_THREADS : no_of_threads);
		//printf("creating %d threads\n",no_of_threads);

		//init the mutex
		if (pthread_mutex_init(&threadlock, NULL)) {
			perror("pthread_mutex_init");
			exit(1);
		}

		//create a thread pool
		for(i = 0; i < no_of_threads; i++)
		{
			thread_id[i] = i;
			//printf("creating thread - %d\n",i);
			if (pthread_create(&ps_thread[i], NULL, (void *)ps_threaded, &thread_id[i]) != 0){
				perror("pthread_create failed");
				exit(FAILURE);
			}

		}

		for (i=0; i <no_of_threads; ++i) {
			rc = pthread_join(ps_thread[i], NULL);
			if(rc)
			{
				perror("Failed to create threads ");
				exit(FAILURE);
			}
		}

	}


	(void) gettimeofday (&elapsed, &timezone);
	timeval_diff(&interval,&elapsed,&start);
	//print the time took to scan

	//stop the alarm
	printf("\n");
	alarm(0);


	printf("Scan took %ld.%ld secs\n",interval.tv_sec,interval.tv_usec);

	//destroy job list at the end
	destroy_joblist(temp_joblist_top);

	//display the results
	print_results();

	//destroy the ip and port lists
	destroy_iplist();
	destroy_portlist();
	destroy_results();


	print_servver_result();
	destroy_servver_results();

	return 0;

}



//find the machine's ipAddress
int find_localip() {
	struct ifaddrs * ifAddrStruct=NULL;
	struct ifaddrs * ifa=NULL;
	void * tmpAddrPtr=NULL;

	getifaddrs(&ifAddrStruct);

	bzero(localip,INET_ADDRSTRLEN);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
		//Check only for eth0!!
		if ((ifa ->ifa_addr->sa_family==AF_INET) && (strcmp(ifa->ifa_name,"eth0") == 0)) {
			tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, localip, INET_ADDRSTRLEN);
			//printf("Local IP Address %s: %s\n", ifa->ifa_name, localip);
		}
	}

	if (ifAddrStruct!=NULL)
		freeifaddrs(ifAddrStruct);

	if(strlen(localip) == 0)//means no eth0 ip found!!
	{
		printf("Couldnt find the machine's ipAdress!!");
		exit(FAILURE);
	}

	return 0;
}


