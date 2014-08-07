#ifndef _MATCH_RULE_H
#define _MATCH_RULE_H

#define MD5_PATH			"Policy.md5"
#define POLICY_PATH			"Policy.json"
#define MODULE_NAME			"nf_match"
#define LOG_PATH 			"nf_log.json"

#define NF_IOC_MAGIC 			'H'
#define NF_IOC_MAXNR			4
#define SET_MATCH_PATTERN_IN 	_IOW(NF_IOC_MAGIC, 0, long unsigned int)
#define SET_MATCH_PATTERN_OUT	_IOW(NF_IOC_MAGIC, 1, long unsigned int)
#define SET_MATCH_SEGMENT_IN	_IOW(NF_IOC_MAGIC, 2, long unsigned int)
#define SET_MATCH_SEGMENT_OUT	_IOW(NF_IOC_MAGIC, 3, long unsigned int)

#define REGULAR 0
#define TEST 1
#define DEFAULT 2

#define IPTOCHAR(ip)				\
		((unsigned char*)&ip)[0],	\
		((unsigned char*)&ip)[1],	\
		((unsigned char*)&ip)[2],	\
		((unsigned char*)&ip)[3]

#define BIT_IP(x) ((unsigned char*)&(x))
#define STR_IP(x) BIT_IP(x)[0], BIT_IP(x)[1], BIT_IP(x)[2], BIT_IP(x)[3]
#define FREE(x) if(x != NULL) {free(x); x = NULL;}
#define FREE_MT(x) if (x) { kfree(x); x = NULL; }
#define FREE_MT_ALL(x) {match_sys_free(x);FREE_MT(x);}

struct hlist_node;
struct hlist_head;
struct tuple_info
{
    unsigned int 	saddr;
	unsigned int 	daddr;
    unsigned short 	sport;
	unsigned short 	dport;
    unsigned char 	proto;
};

struct match_tuple
{
    unsigned int    addr;
    unsigned short  sport;
    unsigned short  dport;
    unsigned char   proto;
    unsigned char   action;
	unsigned char	type;
	unsigned char 	segment;
    
    struct hlist_node	hnode;
};

struct log_info
{
	unsigned int	saddr;
	unsigned int	daddr;
	unsigned short	sport;
	unsigned short	dport;
	unsigned char	proto;
	unsigned char 	action;
};

#define HASHTABLE_NUM_ABC   0x02000
#define HASHTABLE_NUM_ABX   0x08000
#define HASHTABLE_NUM_ADDR  0x08000
#define HASHTABLE_NUM_PORT  0x10000

struct match_table
{
	struct hlist_head *ht_abc;
	struct hlist_head *ht_abx;
	struct hlist_head *ht_axc;
	struct hlist_head *ht_xbc;
	struct hlist_head *ht_addr;
	struct hlist_head *ht_srcp;
	struct hlist_head *ht_dstp;
	struct match_tuple *xxx;
};

struct match_info
{
    int count;
    int dirct;
    struct match_tuple entries[0];
};

struct match_segment
{
	unsigned int mask;
	unsigned int bits;
		
	struct list_head hnode;
};

struct segment_info
{
	int count;
	int dirct;
	struct match_segment entries[0];
};

extern int match_sys_init(void);
extern void match_sys_exit(void);
extern int match_load(struct match_info *minfo, int dir);
extern int segment_load(struct segment_info *sinfo, int dir);
extern unsigned int match_rule_in(struct tuple_info *tuple);
extern unsigned int match_rule_out(struct tuple_info *tuple);

#endif


