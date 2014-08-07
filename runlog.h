#ifndef RUNLOG_H
#define RUNLOG_H

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/syslog.h>
#include <arpa/inet.h>

#include "sqlite3.h"
#include "cJSON.h"
#include "config.h"
#define DB_PATH "nf_log.db"



#define IPTOCHAR(ip) 	\
					((unsigned char*)&ip)[0],	\
					((unsigned char*)&ip)[1],	\
					((unsigned char*)&ip)[2],	\
					((unsigned char*)&ip)[3]


void write_syslog(int priority, const char* description)
{
	openlog("matchd", LOG_ODELAY|LOG_PID, LOG_USER);
	syslog(priority, "%s",  description);
	closelog();		
}

int __sql_exec(sqlite3* db, const char* sql)
{
	if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		return -1;
	}

	return 0;
}


int sql_create_runlog(sqlite3* db)
{
    const char *sql_create_runlog = "CREATE TABLE IF NOT EXISTS		\
									runlog(id INTEGER PRIMARY KEY,	\
									description TEXT NOT NULL,		\
									date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)";
	return __sql_exec(db, sql_create_runlog);

	
}

int sql_create_accesslog(sqlite3* db)
{
	const char *sql_create_accesslog = "CREATE TABLE IF NOT EXISTS		\
										accesslog(id INTEGER PRIMARY KEY,	\
										saddr INTEGER NOT NULL,			\
										daddr INTEGER NOT NULL,			\
										sport INTEGER NOT NULL,			\
										dport INTEGER NOT NULL,			\
										protocol INTEGER NOT NULL,			\
										action INTEGER NOT NULL,			\
										date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)";
	return __sql_exec(db, sql_create_accesslog);
}

int insert_table_runlog(sqlite3* db, const char* description, int priority)
{
	int ret = 0;
	char* sql_insert_runlog = (char *)malloc(strlen(description) + 64);
	
	
	memset(sql_insert_runlog, 0, sizeof(strlen(description) + 64));
	sprintf(sql_insert_runlog, "insert into runlog(description) values('%s')", description);

	ret = __sql_exec(db, sql_insert_runlog);

	printf("insert_table_runlog\n");
	free(sql_insert_runlog);
	
	return ret;
}


int insert_table_accesslog(struct log_info *log)
{
	sqlite3* db;
	int ret;
	
	char* sql = (char*)malloc(sizeof(struct log_info)*4 + 128);
	memset(sql, 0, sizeof(struct log_info)*4 + 128);

	if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
		write_syslog(LOG_ERR, "LOG_ERR: Can not open nf_log.db");
		return -1;
	}

	if (sql_create_accesslog(db) != 0)	{
		sqlite3_close(db);
		write_syslog(LOG_ERR, "LOG_ERR: Can not open table accesslog");
		return -1;
	}

	sprintf(sql, "insert into accesslog(saddr, daddr, sport, dport, protocol, action) values (%d,%d,%d,%d,%d,%d)",	\
			log->saddr, log->daddr, ntohs(log->sport), ntohs(log->dport), log->proto, log->action);

	ret = __sql_exec(db, sql);

	free(sql);
	sqlite3_close(db);
	
	return 0;
}

int runlog(int priority, const char* description)
{
	sqlite3* db = 0;
	
	if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
		write_syslog(LOG_ERR, "LOG_ERR: Can not open nf_log.db");
		return -1;
	}
	
	if (sql_create_runlog(db) != 0) {
		sqlite3_close(db);
		write_syslog(LOG_ERR, "LOG_ERR: Can not open table runlog");
		return -1;
	}
	
	if (insert_table_runlog(db, description, priority) != 0) {
		sqlite3_close(db);
		write_syslog(LOG_ERR, "LOG_ERR: Can not insert into table runlog");
		return -1;
	}
	sqlite3_close(db);

	return 0;
}

int addjson_runlog(char** dbresult, cJSON *root, int row, int column)
{
	cJSON *runlog, *tmp;
	int i = 0;
	
	cJSON_AddItemToObject(root, "runlog", runlog = cJSON_CreateArray());

	for(i = 0; i < row; ++i)
	{
	//	for(j = 0; j < column; ++j)
		cJSON_AddItemToArray(runlog, tmp = cJSON_CreateObject());
		cJSON_AddStringToObject(tmp, "description", dbresult[(i+1)*column + 1]);
		cJSON_AddStringToObject(tmp, "date", dbresult[(i+1)*column + 2]);
	}

	return 0;
}

#define DB_OFFSET(x) dbresult[(i + 1) * column + x]

int addjson_accesslog(char ** dbresult, cJSON *root, int row, int column)
{
	cJSON *accesslog, *tmp;
	int i = 0;
	char ip[32];
	int int_ip = 0;
	
	memset(ip, 0, 32);
	if(get_agentIP(ip, sizeof(ip)-1))
	{
		runlog(LOG_ERR, "Error: get local ip failure");
		return -1;
	}
	cJSON_AddStringToObject(root, "AgentIP", ip);

	cJSON_AddItemToObject(root, "accesslog", accesslog = cJSON_CreateArray());
	
	for (i = 0; i < row; i++)
	{
		cJSON_AddItemToArray(accesslog, tmp = cJSON_CreateObject());

		memset(ip, 0, 32);
		int_ip = atoi(DB_OFFSET(1));
		sprintf(ip, "%d.%d.%d.%d", IPTOCHAR(int_ip));
		cJSON_AddStringToObject(tmp, "saddr", ip);
		
		memset(ip, 0, 32);
		int_ip = atoi(DB_OFFSET(2));
		sprintf(ip, "%d.%d.%d.%d", IPTOCHAR(int_ip));
		cJSON_AddStringToObject(tmp, "daddr", ip);

		cJSON_AddStringToObject(tmp, "sport", DB_OFFSET(3));
		cJSON_AddStringToObject(tmp, "dport", DB_OFFSET(4));
		cJSON_AddStringToObject(tmp, "protocol", strcmp(DB_OFFSET(5), "6") == 0 ? "TCP" : "UDP");
		cJSON_AddStringToObject(tmp, "action", strcmp(DB_OFFSET(6), "0") == 0 ? "DENY" : (strcmp(DB_OFFSET(6), "1") ? "ALLOW" : "TEST") );
		cJSON_AddStringToObject(tmp, "date", DB_OFFSET(7));
	}
	return 0;
}

int stoj()
{
	sqlite3 *db;
	cJSON *root;
	int logexist = 0;
	int row = 0, column = 0;
	char *out;
	char **dbresult;
	
	if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
		write_syslog(LOG_ERR, "LOG_ERR: Can not open nf_log.db");
		return -1;
	}

	root = cJSON_CreateObject();
	
	sqlite3_get_table(db, "select * from accesslog", &dbresult, &row, &column, NULL);
	if(row > 1) {
		logexist = 1;
		if (addjson_accesslog(dbresult, root, row, column) != 0) {
			sqlite3_free_table(dbresult);
			sqlite3_close(db);
			cJSON_Delete(root);
		}	
	}
	sqlite3_free_table(dbresult);
	
	row = 0;
	column = 0;
	
	sqlite3_get_table(db, "select * from runlog", &dbresult, &row, &column, NULL);
	if (row > 1) {
		logexist = 1;
		addjson_runlog(dbresult, root, row, column);
	}
	sqlite3_free_table(dbresult);
	
	out = cJSON_Print(root);
		
    if (logexist) {
		FILE *fp = fopen(LOG_PATH, "w");
		if(fp == NULL) {
			write_syslog(LOG_ERR, "LOG_ERR: Can not create log file");
			free(out);
			sqlite3_close(db);
			cJSON_Delete(root);
			return -1;
		}
		fprintf(fp, out);
		fclose(fp);
	}

	free(out);

	sqlite3_exec(db, "delete from runlog", NULL, NULL, NULL);
	sqlite3_exec(db, "delete from accesslog", NULL, NULL, NULL);		

	sqlite3_close(db);
	cJSON_Delete(root);
	return 0;
}


	
#endif
