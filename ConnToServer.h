#ifndef CONNTOSERVER_H
#define CONNTOSERVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include "config.h"
#include "syslog.h"

/*
*函数名称：	ConnToServer
*函数功能：	与服务端通信，获取服务端ip、策略更新等信息
*调用函数：	get_item_value(),get_agentIP()
*输入：		URL, file save path, server address, flag is to indicate whether the update is forced 
*输出：		0/1
*返回值：	0 is success, -1 is failed
*/

int ConnToServer(const char * URL, const char * file_path, const char* addr, int flag)
{
	
	FILE *fp;
	int sockfd;
	struct sockaddr_in server_addr;
	char port[7] = {0};
    char update_request[256] = {0};
	char agent_ip[20] = {0};
	//struct in_addr server_ip;
	//struct hostent server_hostent;

	if(get_item_value(port, "SERVERPORT") == NULL)
	{
		return -1;
	}

	if(get_agentIP(agent_ip, sizeof(agent_ip)-1))
	{
		return -1;
	}

	//if use domain name
	//server_hostent = gethostbyname(addr);
	//server_ip.s_addr = *(unsigned long*) server_hostent->h_addr;
	//server_addr.sin_addr.s_addr = server_hostent->haddr;
	//sprintf(update_request,"GET %s?AgentIP=%s&MD5_check=%d HTTP/1.1\r\nHost:%s\r\nConnection:Close\r\n\r\n", URL, agent_ip, flag, inet_ntoa(server_ip));
	
	sprintf(update_request,"GET %s?AgentIP=%s&MD5_check=%d HTTP/1.1\r\nHost:%s\r\nConnection:Close\r\n\r\n", URL, agent_ip, flag, addr);
	printf("%s\n", update_request);
	char buf[2];
	if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1)
	{
		fprintf(stderr,"Socket Error:%s\a\n",strerror(errno));
		return -1;
	}
	
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(port));
	server_addr.sin_addr.s_addr = inet_addr(addr);
	memset(server_addr.sin_zero,0,8);

	if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr)) == -1)
	{
		return -1;
	}

	if(send(sockfd,update_request,strlen(update_request),0) == -1)
	{
		return -1;
	}

	
	fp = fopen(file_path,"w+");
	if(!fp)
	{
		return -1;
	}
	int i = 0;

	while(read(sockfd,buf,1) == 1)
	{
		if(i<4)
		{
			if(buf[0] == '\r'||buf[0] == '\n') i++;
			else i = 0;
		}	
		else
		{
	 		fwrite(buf,1,1,fp);
			i++;
			if(i%1204 == 0) fflush(fp);
		}
		}
	fclose(fp);
	close(sockfd);
	return 0;
}

#endif

