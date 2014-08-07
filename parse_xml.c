#include <stdio.h>   
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>   
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <iconv.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <curl/curl.h>

#include "cJSON.h"
#include "linux_list.h"
#include "match_rule.h"

#include "runlog.h"
#include "config.h"
#include "ConnToServer.h"

//update per 5 min
#define UPDATE_PERIOD		5*60
#define BUFSIZE				128			
#define FILE_INCORRECT      2 
#define XML_FREE(x) {xmlFreeDoc(x); xmlCleanupParser();}

/******************************************
 *解析JSON得到的每条规则保存到该结构体中
 *addr:规则中的地址 sport:源端口 dport:目的端口 
 *proto:协议 6：TCP 17：UDP
 *action:执行动作 0：NF_DROP 1:NF_ACCEPT 
 *direct:连接方向 0：IN 1：OUT 
 *type:规则类型 segment:掩码
 *******************************************/
struct policy_rule
{
    unsigned int    addr;
    unsigned short  sport;
    unsigned short  dport;
    unsigned char   proto;
    unsigned char   action;
    unsigned char   direct;
	unsigned char	type;
	unsigned char	segment;
    
    struct list_head lnode;
	struct list_head snode;
};

/**********************************************************
 *作用：检查模块是否已经insmod
 *输入：module:模块名 file_path:模块记录文件，一般为/proc/modules
 *返回值：0：不存在 1：存在 -1：出错
 **********************************************************/
int check_module(const char *module, const char *file_path)
{
	char buf[BUFSIZE];
	
	memset(buf, 0, BUFSIZE);
	FILE *fp = fopen(file_path, "r");
	if(NULL == fp)
	{
		return -1;
	}
	while(fgets(buf, BUFSIZE, fp) != NULL)
	{
		buf[strlen(buf) - 1] = '\0';
		if(strstr(buf, module) != NULL)
		{
			fclose(fp);
			return 1;
		}
	}
	printf("module nf_match was not found\n");
	fclose(fp);
	return 0;
}

/***************************************************
 *作用:向服务端发送策略执行状态
 *输入：status: 0:执行失败 1：执行成功
 *返回值：0：发送成功 -1：发送失败
****************************************************/
int send_status(int status)
{
	CURL *curl;
	CURLcode res;
	char cmd[256] = {0};
	char URL[128] = {0};
	char AgentIP[20] = {0};
	char logaddr[20] = {0};
	
	curl_global_init(CURL_GLOBAL_NOTHING);
	curl = curl_easy_init();
	
	if(curl == NULL)
	{
		printf("curl init failed\n");
		return -1;
	}
	
	if (get_item_value(URL, "Status_URL") == NULL) {
		return -1;
	}

	if (get_item_value(logaddr, "SERVER_ADDR") == NULL) {
		return -1;
	}

	if (get_agentIP(AgentIP, sizeof(AgentIP) - 1) != 0 ) {
		return -1;
	}	
   	
	sprintf(cmd, "http://%s%s?AgentIP=%s&Status=%d", logaddr, URL, AgentIP, status);
	curl_easy_setopt(curl, CURLOPT_URL, cmd);
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		return -1;
	}
	printf("%s\n", cmd);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return 0;
}

/*******************************************************************
 *作用：在JSON节点上添加默认规则
 *输入: rule: rule节点，默认规则挂载在该节点上 addr:服务端IP dir:连接方向
 *输出: 无
********************************************************************/
void __add_default_policy(cJSON *rule, char *addr, const char *dir)
{
	cJSON *default_node;
	
	cJSON_AddItemToArray(rule, default_node = cJSON_CreateObject());

	cJSON_AddStringToObject(default_node, "AccessType", "ALLOW");
	cJSON_AddStringToObject(default_node, "LinkType", dir);
	cJSON_AddStringToObject(default_node, "Address", addr);
	cJSON_AddStringToObject(default_node, "Protocol", "TCP");
	
	if (strcmp(dir, "OUT") == 0) {
		cJSON_AddStringToObject(default_node, "SrcPort", "0");
		cJSON_AddStringToObject(default_node, "DstPort", "0");
	}
	else {
		cJSON_AddStringToObject(default_node, "SrcPort", "0");
		cJSON_AddStringToObject(default_node, "DstPort", "0");
	}

	cJSON_AddStringToObject(default_node, "PolicyType", "DEFAULT");
	
	return;
}

/**********************************************
 *作用：在下载的规则JSON中添加默认可以连接服务端的规则
 *保留模块，如果服务端运用负载均衡的话，怎么控制默认可以
 *连接域名
 *输入：rule:规则节点
 *输出：0:成功 -1：失败
**********************************************/
int add_default_policy(cJSON *rule)
{
	char tmp[20];
	char server_addr[32];

	memset(tmp, 0, 20);
	memset(server_addr, 0, 32);
	
	if (get_item_value(tmp, "SERVER_ADDR") == NULL) {
		runlog(LOG_ERR, "Error: Policy domain config failure");
		return -1;
	}

	sprintf(server_addr, "%s/32", tmp);

	__add_default_policy(rule, server_addr, "IN");
	__add_default_policy(rule, server_addr, "OUT");
	
	return 0;
}

/************************************************
 *作用：将规则由链表转换成数组，并且传到内核中
 *输入：list: 规则链表头节点 seg_list: 网段链表头节点
 *incnt:IN规则数量 outcnt：OUT规则数量，
 *insegcnt: IN网段数量 outsegcnt: OUT网段数量
 *输出： 0：成功 -1：失败
*************************************************/
static int copy_to_kernel(struct list_head *list, struct list_head *seg_list,
				int incnt, int outcnt, int insegcnt, int outsegcnt)
{
    struct match_info *mi = malloc(sizeof(struct match_info) + incnt*sizeof(struct match_tuple));
    struct match_info *mo = malloc(sizeof(struct match_info) + outcnt*sizeof(struct match_tuple));

	struct segment_info *si = malloc(sizeof(struct segment_info) + insegcnt*sizeof(struct match_segment));
	struct segment_info *so = malloc(sizeof(struct segment_info) + outsegcnt*sizeof(struct match_segment));
	
	si->dirct = 0;
	so->dirct = 1;	
	si->count = insegcnt;
	so->count = outsegcnt;

    mi->dirct = 0;
    mo->dirct = 1;
	mi->count = incnt;
	mo->count = outcnt;

	printf("insegcnt[%d] outsegcnt[%d]\n", insegcnt, outsegcnt);	
    fprintf(stderr, "local in cnt[%d]=%ld Byte local out cnt[%d]=%ld Byte\n", incnt, (incnt*sizeof(struct match_tuple)), outcnt, (outcnt*sizeof(struct match_tuple)));
	
	if ((list != NULL) && (seg_list != NULL)) {		
		int i = 0, j = 0;
    	struct policy_rule *node, *n;
    	struct match_tuple *tuple;
		struct match_segment *segment;	

		list_for_each_entry(node, seg_list, snode)
		{
			segment = node->direct == 0 ? &si->entries[i++] : &so->entries[j++];
			segment->mask = node->addr;
			segment->bits = node->segment;
		printf("addr[%d.%d.%d.%d] mask[%d]\n", IPTOCHAR(node->addr),node->segment);
		}

		i = 0;
		j = 0;
	
		list_for_each_entry_safe(node, n, list, lnode)
    	{
			tuple = node->direct == 0 ? &mi->entries[i++] : &mo->entries[j++];
        
			tuple->addr = node->addr;
       		tuple->sport = htons(node->sport);
        	tuple->dport = htons(node->dport);
       	 	tuple->proto = node->proto;
       		tuple->action = node->action;
			tuple->type = node->type;

        fprintf(stderr, "addr:%d.%d.%d.%d sport:%d dport:%d proto:%s action:%d type:%d dir:%s\n" , 
            STR_IP(node->addr), node->sport, node->dport, node->proto == 6?"tcp":"udp", node->action, node->type, node->direct == 0 ? "IN" : "OUT");
			free(node);
    	}
	}
  
   	int fd = open("/dev/MatchConfig", O_CREAT|O_RDWR);
    if (fd == -1)
    {
        fprintf(stderr, "open device file /dev/MatchConfig was failed!\n");
        return -1;
    }
    
	ioctl(fd, SET_MATCH_SEGMENT_IN, si);
	ioctl(fd, SET_MATCH_SEGMENT_OUT, so);
	ioctl(fd, SET_MATCH_PATTERN_IN, mi);
	ioctl(fd, SET_MATCH_PATTERN_OUT, mo);
    close(fd);

	FREE(mi);
	FREE(mo);
	FREE(si);
	FREE(so);
	
	return 0;
}


int set_agent_status(int flag)
{
	flag = (flag << 4) | (check_module(MODULE_NAME ,"/proc/modules"));

	switch(flag)
	{
		case 0x11:	return 0;									//agent enable and modlue exist

		case 0x10:	runlog(LOG_ERR, "Error: can not exec policy, module nf_match not exist");
					return -1;

		case 0x00: 	runlog(LOG_ERR, "Error: module nf_match not exist");
                    return -1;

		case 0x01:	if(copy_to_kernel(NULL, NULL, 0, 0, 0, 0) != 0)
					{
						runlog(LOG_ERR, "Error: Disable agent failed");
                        return -1;
		            }
                    runlog(LOG_INFO, "INFO: agent is disabled");
                    return 1;

		default:	break;
	}

    return -1;
        
}


/************************************************************************
 *作用：规则完整性检查
 *输入：规则节点
 *输出: 0: 规则不完整 1：规则完整
 ***********************************************************************/
int rule_check(cJSON *item)
{
	return ((cJSON_GetObjectItem(item, "AccessType") != NULL)	&&	\
			(cJSON_GetObjectItem(item, "LinkType") != NULL)		&&	\
			(cJSON_GetObjectItem(item, "Address") != NULL)			&&	\
			(cJSON_GetObjectItem(item, "Protocol") != NULL)		&&	\
			(cJSON_GetObjectItem(item, "SrcPort") != NULL)		&&	\
			(cJSON_GetObjectItem(item, "DstPort") != NULL)		&&	\
			(cJSON_GetObjectItem(item, "PolicyType") != NULL));
}

/*******************************************************************************
 *作用：对每个规则进行解析，并且将规则解析为policy结构体和网段保存在链表中
 *输入：item: 每个rule的节点 list:规则链表头节点 seg_list：网段节点头节点
 *incnt:IN规则数量 outcnt：OUT规则数量 insegcnt：IN网段数量 outsegcnt:OUT网段数量 
*输出:无
*******************************************************************************/
void parseRule(cJSON *item, struct list_head *list, struct list_head *seg_list, 
				int *incnt, int *outcnt, int *insegcnt, int *outsegcnt) 
{

	if (item == NULL)
		return;

	if (!rule_check(item))
		return;

	int seg_flag = 0;
    struct policy_rule *rule, *node;
	struct list_head *pos;   
	char *ip;

	pos = seg_list;

    rule = malloc(sizeof(struct policy_rule));
    memset(rule, 0, sizeof(struct policy_rule));

	
	rule->sport = atoi(cJSON_GetObjectItem(item, "SrcPort")->valuestring);
	rule->dport = atoi(cJSON_GetObjectItem(item, "DstPort")->valuestring);
	rule->type = strcmp(cJSON_GetObjectItem(item, "PolicyType")->valuestring, "TEST") == 0 ? TEST: \
	(strcmp(cJSON_GetObjectItem(item, "PolicyType")->valuestring, "DEFAULT") == 0 ? DEFAULT : REGULAR);
	rule->action = strcmp(cJSON_GetObjectItem(item, "AccessType")->valuestring, "ALLOW") == 0 ? 1 : 0;
	
	if (strcmp(cJSON_GetObjectItem(item, "LinkType")->valuestring, "IN") == 0) {
		(*incnt)++;
		rule->direct = 0;
	}
	else {
		(*outcnt)++;
		rule->direct = 1;
	}

	rule->proto = strcmp(cJSON_GetObjectItem(item, "Protocol")->valuestring, "TCP") == 0 ? 6 : 17;
	
	ip = cJSON_GetObjectItem(item, "Address")->valuestring;
	if (strcmp(ip, "0") == 0) {
		rule->addr = 0;
		rule->segment = 0;
	}

	else {
		char *p;
		if (((p = strrchr((const char *)ip, '/')) != NULL))
			*p = '\0';
		else {
			printf("ip:%s format is incorrect\n", ip);
			free(rule);
			return;
		}
			
		rule->segment = atoi((const char*)(p + 1));
		rule->addr = (inet_addr((const char *)ip)) & htonl((0XFFFFFFFF << (32 - rule->segment)));

	
		if (rule->segment != 32)
		{	
			list_for_each_entry(node, seg_list, snode)
			{
				if(node->segment >= rule->segment)
					pos = &(node->snode);
				if ((node->addr == rule->addr)		 	&& 
					(node->segment == rule->segment)	&&
					(node->direct == rule->direct))
				{	
					seg_flag = 1;
				}
			}
			if (!seg_flag)
			{
				list_add_head(&rule->snode, pos);			
				rule->direct == 0 ? ((*insegcnt)++) : ((*outsegcnt)++);
			}
		}
	}

 	list_add_tail(&rule->lnode, list);

	
}
/*************************************************
作用：解析策略，生成链表，并且发到内核
输入：rule: JSON规则数组的节点
输出： 0：成功 -1：失败
*************************************************/
int parsePolicy(cJSON *rule)
{
	int incnt = 0, outcnt = 0;
	int insegcnt = 0, outsegcnt = 0;
	struct list_head list;
	struct list_head seg_list;
	int rule_count;

    INIT_LIST_HEAD(&list);
	INIT_LIST_HEAD(&seg_list); 

	rule_count = cJSON_GetArraySize(rule);
	
	for (; rule_count > 0; rule_count--) {
		parseRule(cJSON_GetArrayItem(rule, rule_count-1), &list, &seg_list, \
				&incnt, &outcnt, &insegcnt, &outsegcnt);
	}

	if (copy_to_kernel(&list, &seg_list, incnt, outcnt, insegcnt, outsegcnt) != 0)
		return -1;
	return 0;
}

/*********************************************************
 *作用：解析JSON文件，作一些必要检查
 *输入：JSON文件路径
 *输出： 0:成功 -1：失败
*********************************************************/
static int parseDoc(const char *filename)
{
	cJSON *root, *node, *tmp;
	int flag;	

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)	{
		runlog(LOG_ERR, "Error: Policy file not found");
		return FILE_INCORRECT;
	}
	fseek(fp, 0, SEEK_END);

	long len = ftell(fp);
	if (len <= 0) {
		runlog(LOG_ERR, "Error:Policy file is empty");
		return FILE_INCORRECT;
	}
	fseek(fp, 0, SEEK_SET);

	char *data = (char*)malloc(len+1);

	fread(data, 1, len, fp);
	fclose(fp);
	
		
	root = cJSON_Parse(data);
	if (root == NULL) {
		runlog(LOG_ERR, "Error: Incorrect policy file");
		free(data);
		return FILE_INCORRECT;
	}

	
	if ((node = cJSON_GetObjectItem(root, "check")) == NULL) {
		runlog(LOG_ERR, "Error: Incorrect policy file format");
		free(data);
		cJSON_Delete(root);
		return FILE_INCORRECT;
	}

	if ((tmp = cJSON_GetObjectItem(node, "permit")) == NULL) {
		runlog(LOG_ERR, "Error: Incorrect policy file format");
		free(data);
		cJSON_Delete(root);
		return FILE_INCORRECT;
	}
	
	flag = atoi(tmp->valuestring);
	if (set_agent_status(flag) != 0){
		free(data);
		cJSON_Delete(root);
		return -1;
	}

	if ((tmp = cJSON_GetObjectItem(node, "ModifyMark")) == NULL) {
		free(data);
		cJSON_Delete(root);
		runlog(LOG_ERR, "Error: Incorrect policy file format");
		return FILE_INCORRECT;
	}
	
	if (atoi(tmp->valuestring) == 0) {
		free(data);
		cJSON_Delete(root);
		runlog(LOG_INFO, "Info: No policy update exist");
		return 0;
	}
	
	tmp = cJSON_GetObjectItem(root, "rule");
	
	if (tmp == NULL)	{
		free(data);
		cJSON_Delete(root);
		if(copy_to_kernel(NULL, NULL, 0, 0, 0, 0) != 0)	{
			runlog(LOG_ERR, "Policy exec failure");
            return -1;
		}
		return 0;
	}
	add_default_policy(tmp);

	if (parsePolicy(tmp) != 0) {
		free(data);
		cJSON_Delete(root);
		return -1;
	}

	cJSON_Delete(root);
	free(data);

	return 0;
}

/*********************************************************************
 *作用：解析JSON，记录结果发送到服务端
 *输入：无
 *输出：无
*********************************************************************/
void exec_policy(void)
{	
	int parse_status = parseDoc(POLICY_PATH);
    if (parse_status == 0) 
        runlog(LOG_INFO, "Info: Policy parse success");

    if (parse_status == FILE_INCORRECT)
        rename(POLICY_PATH, "Policy_Incorrect.json");   
    
	// successful : 1      failure:	0
	parse_status = (parse_status == 0) ? 1 : 0;
	if (send_status(parse_status) != 0) {
		runlog(LOG_ERR, "Error: Policy exec status update failed");
	}
}

/*******************************************************************
 *作用：向服务端发送策略更新请求，并且下载MD5和策略文件
 *输入：flag：更新标志 0：正常更新  1：强制更新
 *输出：-1：下载失败 0：下载成功
********************************************************************/
int download_policy(int flag)
{
	char temp[128] = {0};
	char server_addr[64] = {0};

	runlog(LOG_INFO, "Info: Policy update begin.");

	if (get_item_value(server_addr, "SERVER_ADDR") == NULL) {
		runlog(LOG_ERR, "Error: Policy domain config failure.");
		return -1;
	}
	
	//policy_addr and log_addr check 


	/*if(addr_check(inet_ntoa(logaddr), inet_ntoa(policyaddr), server_ip) != 0)
	{
		runlog(LOG_INFO, "Info: the address of :server has changed");
		exec_policy(DEFAULT_POLICY_PATH, inet_ntoa(logaddr), inet_ntoa(policyaddr), server_ip);
	}*/
	
	memset(temp, 0, 128);
	if(get_item_value(temp, "MD5") == NULL)
	{
		runlog(LOG_ERR, "Error: Can not get Policy server configuration");
		return -1;
	}

	if(ConnToServer(temp, MD5_PATH, server_addr, 0) == -1)
	{
		runlog(LOG_ERR, "Error: download Policy failed");
		return -1;
	}
	
	memset(temp, 0, 128);
	if(get_item_value(temp, "URL") == NULL)
	{
		runlog(LOG_ERR, "Error: Can not get Policy server configuration");
		unlink(MD5_PATH);
		return -1;
	}
			
	if((ConnToServer(temp, POLICY_PATH, server_addr, flag)) == -1)
	{
		runlog(LOG_ERR, "Error: Download Policy failed");
		unlink(MD5_PATH);
		return -1;
	}
	return 0;
}

/**********************************************
 *作用：校验下载的策略的MD5
 *输入：无
 *返回值：0：校验成功 其他：校验失败
**********************************************/
int md5_check(void)
{
    char cmd[32] = {0};
   
     if ((access(POLICY_PATH, F_OK) != 0) ||
        (access(MD5_PATH, F_OK) != 0))  
        return -1;
    
    sprintf(cmd, "md5sum -c %s", MD5_PATH);
    
    return (system(cmd));
}

/*************************************************

Function: sig_alarm

Description: 策略更新周期到达时执行，向服务端下拉策略并且进行解析 

Others: 执行过程会调用runlog记录日志

*************************************************/
void sig_alarm(int signo)
{
	if (download_policy(0) != 0)
		return;

	if(md5_check() != 0)
	{
		runlog(LOG_ERR, "Warning: MD5 check failed");

		unlink(MD5_PATH);
		unlink(POLICY_PATH);
		
		if (download_policy(1) != 0)
			return;
		if (md5_check() != 0)
		{
			runlog(LOG_ERR, "Error: MD5 not match.");
			return;
		}
	}
	exec_policy();
}

/*rewirte the call_back function of SIG_ALARM*/
void alarm_rewrite(int time)
{
	struct sigaction newact,oldact;
	unsigned int unslept;
	
	newact.sa_handler = sig_alarm;
	sigemptyset(&newact.sa_mask);
	newact.sa_flags = 0;
	sigaction(SIGALRM, &newact, &oldact);

	alarm(time);
	pause();

	unslept = alarm(0);
	sigaction(SIGALRM, &oldact, NULL);
}

/*
*函数名称：	main
*函数功能：	重写定时函数，设置定时时间进行策略更新
*输入：		无
*输出：		无
*/
int main(int argc, char* argv[])
{
//	daemon(1,0);
	alarm_rewrite(1);
	while(1)
	{
		struct sigaction newact,oldact;
		unsigned int unslept;
	
		newact.sa_handler = sig_alarm;
		sigemptyset(&newact.sa_mask);
		newact.sa_flags = 0;
		sigaction(SIGALRM, &newact, &oldact);

		alarm(UPDATE_PERIOD);
		pause();

		unslept = alarm(0);
		sigaction(SIGALRM, &oldact, NULL);
	}
	
	//parseDoc(argv[1]);
	return 0;
}


