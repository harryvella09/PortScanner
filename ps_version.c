#include "ps_version.h"

servver_result_t * servver_result_masterlist_top = NULL;
int serv_ports[6] = {22,24,43,80,110,143};



int isversion_needed(int portno,char *ip)
{
	int i = 0;
	servver_result_t *version_rslt_iterator = servver_result_masterlist_top;

	for(i = 0; i < 6; i++)
	{
		if(portno == serv_ports[i])
			break;
	}


	while(version_rslt_iterator)
	{
		if((strcmp(ip,version_rslt_iterator->ip) == 0) && (strlen(version_rslt_iterator->version[i]) != 0))
		{//already updated the result earlier
			return FALSE;
		}
		version_rslt_iterator = version_rslt_iterator->next;
	}

	return TRUE;

}

int version_detection(int portno, char * dest_ip)
{
	int sockfd;
	struct sockaddr_in dest_addr;
	struct hostent * hostinfo;
	char * recvbuf = NULL;
	int bytestoRead = 250;
	char * ServerName = NULL;
	char version[6][50];
	int i,len = 0;
	char * temp = NULL;
	char * word = NULL;
	//char * newword = NULL;
	char sep[] = " ";
	char dataTosend[10] = "dagwood";

	servver_result_t *current_servver_result = NULL;

	//allocate memory for buffer
	recvbuf = (char *)malloc(300);
	bzero(recvbuf,300);

	//allocate memory for storing the result
	current_servver_result = prepare_servversion_rslt(dest_ip);

	//Socket Creation
	sockfd = socket(AF_INET,SOCK_STREAM,0); 
	if (sockfd < 0)
			{
					perror("Socket Creation Failed\n");
					return FALSE;
			}
	

	/* Initialize the sockaddr_in  */
	if(!(hostinfo = gethostbyname(dest_ip))){
    fprintf(stderr,"ERROR: Invalid host name %s",dest_ip);
    return FALSE;
	}
	
	dest_addr.sin_family = hostinfo->h_addrtype; //AF_INET
	bcopy((char *) hostinfo->h_addr,
        (char *) &(dest_addr.sin_addr.s_addr),
        hostinfo->h_length);

    dest_addr.sin_port = htons(portno); 
	
	//establish connection
	if (connect(sockfd,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0)
			{
					printf("\nService Detection for port %d failed due to connect error",portno);
					for(i=0;i<6;i++)
					{
						if(serv_ports[i] == portno) break;
					}
					strcpy(current_servver_result->version[i],"UNKNOWN");
					push_servver_result(current_servver_result,i);
					  
					return FALSE;
					//exit(EXIT_FAILURE);
			}


	switch(portno){

		case 22: if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
				{
						//printf("Receiving message of specified length failed\n");
						free(recvbuf);
						return FALSE;
				}
				//printf("Message received is %s\n",recvbuf);
				len = strlen((char *)recvbuf);
						
						  for (i=0;i<=len;i++)
						  {
							if (recvbuf[i] == '\n') break;
							version[SSH][i] = recvbuf[i];
						  }
						  version[SSH][i] = '\0';
					  
					  //printf("Version : %s\n",version[SSH]);
					  strcpy(current_servver_result->version[SSH],version[SSH]);
					  push_servver_result(current_servver_result,SSH);
					  
				break;


		case 24:  if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
				{
						//printf("Receiving message of specified length failed\n");
						free(recvbuf);
						return FALSE;
				}
				//printf("Message received is %s\n",recvbuf);
				temp = recvbuf;
				//extract the server version using strtok
				for(word = strtok(temp, sep), i=0;
					(word && i < 6);
					word = strtok(NULL,sep), i++){
					//printf("i = %d word = %s\n",i,word);
					switch(i){
						case 2://service version
							strcpy(version[SMTP],word); strcat(version[SMTP]," "); break;
						case 3://service version
							strcat(version[SMTP],word); strcat(version[SMTP]," "); break;
						case 4://service version
							strcat(version[SMTP],word); strcat(version[SMTP]," "); break;
						case 5://service version
							strcat(version[SMTP],word);	break;
								
						default: break;
					}
				}
				//printf("Version : %s\n",version[SMTP]);
				strcpy(current_servver_result->version[SMTP],version[SMTP]);
				push_servver_result(current_servver_result,SMTP);
				break;
				
		case 110: if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
				{
						//printf("Receiving message of specified length failed\n");
						free(recvbuf);
						return FALSE;
				}
				//printf("Message received is %s\n",recvbuf);
				temp = recvbuf;
				//extract the server version using strtok
				for(word = strtok(temp, sep), i=0;
					(word && i < 3);
					word = strtok(NULL,sep), i++){
					//printf("i = %d word = %s\n",i,word);
					switch(i){
						case 1://service version
							strcpy(version[POP],word);
							break;
						default: break;
					}
				}
				//printf("Version : %s\n",version[POP]);
				strcpy(current_servver_result->version[POP],version[POP]);
				push_servver_result(current_servver_result,POP);
				break;

		case 143:

			 if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
				{
						//printf("Receiving message of specified length failed\n");
						free(recvbuf);
						return FALSE;
				}
			//printf("Message received is %s\n",recvbuf);
			temp = (char *)malloc(strlen(recvbuf));
			memcpy(temp,recvbuf,strlen(recvbuf));
			
			strcpy(version[IMAP],"Version: ");
				//extract the server version using strtok
				for(word = strtok(temp, sep), i=0;
					(word && i < 4);
					word = strtok(NULL,sep), i++){
					//printf("i = %d word = %s\n",i,word);
					switch(i){
						case 3://service version
							strcat(version[IMAP],word);
						default: break;
					}
				}
				//printf("Version : %s\n",version[IMAP]);
				strcpy(current_servver_result->version[IMAP],version[IMAP]);
				push_servver_result(current_servver_result,IMAP);
				free(temp);
				break;

		case 43:	if (sendData(sockfd,dataTosend,10) == FAILURE) return FALSE;
					if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
						{
								//printf("Receiving message of specified length failed\n");
								free(recvbuf);
								return FALSE;
						}
					  //printf("Message received is %s\n",recvbuf);
					  ServerName = strstr(recvbuf, "Server Version");
					  if (ServerName == NULL)
						  {
						  	  //printf("String not found\n");
						  }
					  else	
					  {
							//printf("Server : %s\n",ServerName);
							ServerName += 15;
							len = strlen(ServerName);
						
						  for (i=0;i<=len;i++)
						  {
							if (ServerName[i] == '\n') break;
							version[WHOIS][i] = ServerName[i];
						  }
						  version[WHOIS][i] = '\0';
						  //printf("Version : %s\n",version[WHOIS]);
					  }
					  strcpy(current_servver_result->version[WHOIS],version[WHOIS]);
					  push_servver_result(current_servver_result,WHOIS);
					  break;
						
		case 80:	if (sendHttpQuery("httprequest",sockfd) == FAILURE) return FALSE;
					if (recvData(sockfd, recvbuf, bytestoRead) == FAILURE)
						{
								printf("Receiving message of specified length failed\n");
								free(recvbuf);
								return FALSE;
						}
					//printf("Message received is %s\n",recvbuf);
					ServerName = strstr(recvbuf, "Server");
					  if (ServerName == NULL)
					  {
						  printf("Http Server Name String not found\n");
					  }
					  else	
					  {
							//printf("Server : %s\n",ServerName);
							ServerName += 8;
							len = strlen(ServerName);
						
						  for (i=0;i<=len;i++)
						  {
							if (ServerName[i] == '\n') break;
							version[HTTP][i] = ServerName[i];
						  }
						  version[HTTP][i] = '\0';
						  //printf("Version : %s\n",version[HTTP]);
					  }
					 strcpy(current_servver_result->version[HTTP],version[HTTP]);
					 push_servver_result(current_servver_result,HTTP);
					 break;

	}
	free(recvbuf);
	close(sockfd);
return TRUE;
} 



//Write data into the socket and return SUCCESS/ FAILURE status.
int sendData(int sockfd, char *data, int dataLen)
{	
		char * mydata = data;
	int bytesSent = 0, totalBytesSent = 0, bytesToSend = dataLen;
//	printf("Bytes to send: %d\nprinting hs_msg\n", bytesToSend);
	
			//write every byte of mypacket onto the socket...
			while (bytesToSend > 0)
			{
				bytesSent = write(sockfd, mydata, bytesToSend);
				if (bytesSent > 0)
				{
					//printf("%d Bytes sent successfully!!\n", bytesSent);
					totalBytesSent += bytesSent;
					bytesToSend -= bytesSent;
					mydata += bytesSent;
				}
				else
				{
					perror("Sending data failed!!");
					return FAILURE;
				}
			}

	return SUCCESS;

}


//Receive data from the socket and return SUCCESS/FAILURE status
int recvData(int sockfd, char *data, int bytesToRead)
{
	void *recvbuffer = data;
	int bytesRead = 0;
	//printf("in recvdata\n");
	
		bytesRead = recv(sockfd, recvbuffer, bytesToRead, 0);
		if (bytesRead < 0)
		{
			printf("Reading data from socket %d failed!!\n",sockfd);
			return FAILURE;
		}
		else if (bytesRead == 0)
		{
			printf("No data to read from socket %d\n",sockfd);
			return FAILURE;
		}
		//printf("bytesRead : %d\n",bytesRead);
	return SUCCESS;
}

//send data from a file
int sendHttpQuery(const char * filename,int sockfd)
{
FILE * inputStream;
char input[BUF_LEN];
void * tempBuff;
int bytesRead = 0, totalBytesRead = 0;
int bytesSent = 0, totalBytesSent = 0;

inputStream = fopen(filename,"r"); //opening the file in read mode
	if(inputStream == NULL)
        {
                printf("Error opening the file with filename %s, Service Detection not done for port 80\n",filename);
                return FAILURE;
        }
	

	while(TRUE)
	{

                memset(&input,0,BUF_LEN);       //clear the buffer before writing anything into it...
		 	bytesRead = read(fileno(inputStream),&input,BUF_LEN);


		if(bytesRead == 0)
                {
                        //printf("End of file reached\n");
                        break;
                }
                else if(bytesRead < 0)
                {
                        perror("Error occurred while reading the file :");
                        fclose(inputStream);
                        return FAILURE;
                }
                else
                {//handling the socket write
                        totalBytesRead += bytesRead;

                        tempBuff = input;
                        while(bytesRead > 0)
                        {
                                bytesSent = write(sockfd,tempBuff,bytesRead);
                                if(bytesSent > 0)
                                {
                                        //printf("%d Bytes sent in this iteration successfully!!\n",bytesSent);
                                        totalBytesSent += bytesSent;
                                        bytesRead -= bytesSent;
                                        tempBuff += bytesSent;
                                }
                                else
                                {
                                        perror("Sending data failed!!");
                                        fclose(inputStream);
                                        return FAILURE;
                                }
                        }
                        //printf("totalbytes read : %d\n",totalBytesRead);
		}
	}

fclose(inputStream);//close the file pointer
return SUCCESS;
}

servver_result_t *prepare_servversion_rslt(char *ip)
{
	servver_result_t *temp_result = NULL;
	//allocate memory and store the ip address in the version result
	temp_result = (servver_result_t *)malloc(sizeof(servver_result_t));
	memcpy(temp_result->ip,ip,INET_ADDRSTRLEN);
	temp_result->next = NULL;
	return temp_result;
}

void push_servver_result(servver_result_t *result, int index)
{
	int i = 0;
	servver_result_t *temp_result = NULL;
	servver_result_t *result_top = servver_result_masterlist_top;

	while(result_top)
	{
		if((strcmp(result_top->ip,result->ip) == 0))
			{//already updated the result earlier
				break;
			}
		result_top = result_top->next;
	}

	if(result_top == NULL)
	{//if the result for this ip was never updated ... create new result_t and add it to the top
		temp_result = (servver_result_t *)malloc(sizeof(servver_result_t));
		//update the values
		memcpy(temp_result->ip,result->ip,INET_ADDRSTRLEN);
		for(i=0;i<6;i++)
		{
			bzero(temp_result->version[i],50);
		}
		//update the next pointer
		temp_result->next = servver_result_masterlist_top;
		servver_result_masterlist_top = temp_result;
		//result_list_count++;
	}
	else
	{
		temp_result = result_top;
		//printf("Update : IP - %s | Prt - %d  | Srv - %s ",temp_result->ip,temp_result->portno,temp_result->service);
	}


	//update the new result
	memcpy(temp_result->version[index],result->version[index],50);
		
	//printf("New : IP - %s | Version %s ",temp_result->ip,temp_result->version[index]);
	
	//free the earlier malloc'ed result structure
	free(result);
}



void print_servver_result()
{
	int i = 0;
	servver_result_t *result_top = servver_result_masterlist_top;

	if(result_top == NULL)
	{
		printf("\nService Detection is not done as given ports are not in required range!\n");
	
	}
	else
	{
		printf("\nSERVICE VERSION DETECTION RESULTS\n");
		printf("---------------------------------\n");
		while(result_top)
		{
			printf("\nIP ADDRESS : %s\n",result_top->ip);
			printf("---------------------------------\n");
			printf("Port\t\tService Version\n");
			printf("---------------------------------\n");
		
			for(i=0;i<6;i++)
			{
				if (strlen(result_top->version[i]) != 0)
				printf("%d\t\t%s\n",serv_ports[i],result_top->version[i]);
			}
			printf("---------------------------------\n");
		
			result_top = result_top->next;
		}
	}
}

void destroy_servver_results()
{
	servver_result_t *node = NULL;
	servver_result_t *prev_node = NULL;
	node = servver_result_masterlist_top;
	servver_result_masterlist_top = NULL;
	//result_list_count = 0;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}
