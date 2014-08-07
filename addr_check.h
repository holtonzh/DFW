#ifndef ADDR_CHECK_H
#define ADDR_CHECK_H

#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

#include "config.h"

#ifndef POLICY_PATH
#define DEFAULT_POLICY_PATH "Default_Policy.xml"
#endif

#ifndef CONFIG_PATH
#define CONFIG_PATH "agent.conf"
#endif

int config_modify(const char *policyaddr, const char *logaddr)
{
	char buf[128] = {0};
	FILE *fp = fopen(CONFIG_PATH, "r");
	FILE *ftmp = fopen("config.tmp", "w");
	if(fp == NULL)
	{
		printf("1\n");
		return -1;
	}
	if(ftmp == NULL)
	{
		fclose(fp);
		return -1;
	}
	while(fgets(buf, 128, fp) != NULL)
	{
		if(buf[0] == 0x0a) 
			continue;
		if((strstr(buf, "POLICYADDR") != NULL) || (strstr(buf, "LOGADDR") != NULL))
			continue;
		fprintf(ftmp, buf);
	}
	fprintf(ftmp, "LOGADDR=%s\n", logaddr);
	fprintf(ftmp, "POLICYADDR=%s\n", policyaddr);
	//if there is no POLICYADDR AND LOGADDR, needs write in
	fclose(ftmp);
	fclose(fp);
	remove(CONFIG_PATH);
	rename("config.tmp", CONFIG_PATH);
	return 0;
}

int __addr_check(char *needle, char *value)
{
	char result[32] = {0};
	if(get_item_value(result, needle) == NULL)
	{
		printf("patten not found\n");
		return 0;
	}
	if(strcmp(value, (get_item_value(result, needle))) != 0)
	{
		printf("patten not match\n");
		return 0;
	}
	printf("patten match, the %s is: %s\n", needle, result);
	return 1;
}


void add_childnode(const xmlNodePtr root, const char* AccessType, const char* LinkType, const char* Protocol, const char * IP, const char * Src_Port, const char* Dst_Port)
{
	char ip_mask[32];
	xmlNodePtr curNode;
	curNode = xmlNewNode(NULL, BAD_CAST"Rule");
	xmlAddChild(root, curNode);

	sprintf(ip_mask, "%s/%d", IP, 32);	

	xmlNewTextChild(curNode, NULL, BAD_CAST"AccessType", BAD_CAST(AccessType));
	xmlNewTextChild(curNode, NULL, BAD_CAST"LinkType", BAD_CAST(LinkType));
	xmlNewTextChild(curNode, NULL, BAD_CAST"Protocol", BAD_CAST(Protocol));
	xmlNewTextChild(curNode, NULL, BAD_CAST"IP", BAD_CAST(ip_mask));
	xmlNewTextChild(curNode, NULL, BAD_CAST"SrcPort", BAD_CAST(Src_Port));
	xmlNewTextChild(curNode, NULL, BAD_CAST"DstPort", BAD_CAST(Dst_Port));
}

int add_default_policy(const char* file_path, const xmlDocPtr doc, const xmlNodePtr root, const char *logaddr, const char *policyaddr, const char *serveraddr)
{
	xmlNodePtr	curNode;
	
	curNode = xmlNewNode(NULL, BAD_CAST"Policy");
	xmlAddChild(root, curNode);
	
	xmlNewTextChild(curNode, NULL, BAD_CAST"PolicyType", BAD_CAST"DEFAULT");
	
	add_childnode(curNode, "ALLOW", "OUT", "TCP", logaddr, "0", "80");	
	add_childnode(curNode, "ALLOW", "IN", "TCP", logaddr, "80", "0");
	add_childnode(curNode, "ALLOW", "OUT", "TCP", policyaddr, "0", "80");
	add_childnode(curNode, "ALLOW", "IN", "TCP", policyaddr, "80", "0");
	add_childnode(curNode, "ALLOW", "OUT", "TCP", serveraddr, "0", "80");
	add_childnode(curNode, "ALLOW", "IN", "TCP", serveraddr, "80", "0");

	int nRel = xmlSaveFile(file_path, doc);
	if(nRel == -1)
	{
		return -1;
	}	
	return 0;
}

int addr_check(char *logaddr, char *policyaddr, const char *serveraddr)
{
	xmlDocPtr	doc;
	xmlNodePtr	root;
	if( __addr_check("LOGADDR", logaddr) && __addr_check("POLICYADDR", policyaddr))
	{
		printf("go on download policy\n");
		return 0;
	}
	//create policy xml
	if(access(DEFAULT_POLICY_PATH, F_OK) == 0)
	{
		if(unlink(DEFAULT_POLICY_PATH) != 0)
		{
			return -1;
		}
	}
	doc = xmlNewDoc(BAD_CAST"1.0");
	root = xmlNewNode(NULL, BAD_CAST"Policys");
	xmlDocSetRootElement(doc, root);
	xmlNewProp(root, BAD_CAST"Status", BAD_CAST"1");

	int nRel = xmlSaveFile(DEFAULT_POLICY_PATH, doc);
	if(nRel == -1)
	{
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return -1;
	}	

	xmlFreeDoc(doc);
	xmlCleanupParser();
	
	if(config_modify(policyaddr, logaddr) != 0)
	{
		printf("modify agent.conf failed\n");
	}
	
	return 1;
}

#endif
