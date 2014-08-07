
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <asm/uaccess.h>

#include <linux/time.h>

#include "match_rule.h"
#include "ipc.h"

//#define BIT_IP(x) ((unsigned char*)&(x))
//#define STR_IP(x) BIT_IP(x)[0], BIT_IP(x)[1], BIT_IP(x)[2], BIT_IP(x)[3]

#define NF_TEST 2
#define MAX_COUNT 16384

#define TYPE_CHECK(lock, priority) 	({if (node->type == DEFAULT) {	\
			spin_unlock_bh(&lock);			\
			return node->action;			\
		}									\
		if (node->type != TEST){		\
			if (flag == priority)			\
				flag = 0;					\
			action = node->action;			\
			goto out_action;				\
		}									\
		flag = priority;})	

#define TYPE_CHECK_IN(priority)	TYPE_CHECK(in_spinlock, priority)
#define TYPE_CHECK_OT(priority)	TYPE_CHECK(ot_spinlock, priority)

static struct match_segment *mt_in_array_seg;
static struct match_segment *mt_ot_array_seg;
static struct match_segment *in_array_seg;
static struct match_segment *ot_array_seg;

static struct match_table *mt_in_tcp;
static struct match_table *mt_in_udp;
static struct match_table *mt_ot_tcp;
static struct match_table *mt_ot_udp;
static struct match_tuple **mt_in_array_addr;
static struct match_tuple **mt_ot_array_addr;

static int in_index = 0;
static int ot_index = 0;

static int insegcnt = 0;
static int otsegcnt = 0;
static int mt_insegcnt = 0;
static int mt_otsegcnt = 0;


struct timeval start;
struct timeval end;
unsigned int timeuse;


static DEFINE_SPINLOCK(in_spinlock);
static DEFINE_SPINLOCK(ot_spinlock);

////////////////////////////////////////////////////////////
// static function

static void htable_init(struct match_table *mt)
{
    int i, buckets;
   // memset(mt, 0, sizeof(struct match_table));
	memset(mt->ht_abc, 0, HASHTABLE_NUM_ABC);
	memset(mt->ht_abx, 0, HASHTABLE_NUM_ABX);
	memset(mt->ht_axc, 0, HASHTABLE_NUM_ABX);	
	memset(mt->ht_xbc, 0, HASHTABLE_NUM_ABX);
	memset(mt->ht_addr, 0, HASHTABLE_NUM_ADDR);	
	memset(mt->ht_srcp, 0, HASHTABLE_NUM_PORT);
	memset(mt->ht_dstp, 0, HASHTABLE_NUM_PORT);
	mt->xxx = NULL;
    
	buckets = HASHTABLE_NUM_ABC;
    for (i=0; i<buckets; ++i)
    {
        INIT_HLIST_HEAD(&mt->ht_abc[i]);
    }
    
    buckets = HASHTABLE_NUM_ABX;
    for (i=0; i<buckets; ++i)
    {
        INIT_HLIST_HEAD(&mt->ht_abx[i]);
        INIT_HLIST_HEAD(&mt->ht_axc[i]);
        INIT_HLIST_HEAD(&mt->ht_xbc[i]);
    }
    
    buckets = HASHTABLE_NUM_ADDR;
    for (i=0; i<buckets; ++i)
    {
        INIT_HLIST_HEAD(&mt->ht_addr[i]);
    }
    
    buckets = HASHTABLE_NUM_PORT;
    for (i=0; i<buckets; ++i)
    {
        INIT_HLIST_HEAD(&mt->ht_srcp[i]);
        INIT_HLIST_HEAD(&mt->ht_dstp[i]);
    }
}

static unsigned int mkhash_addr(unsigned int addr, unsigned int mask)
{
    return jhash_1word(addr, 0) % mask;
}

static unsigned int mkhash_tuple(struct tuple_info *tuple, int mask)
{
    unsigned int hash;	
    hash = jhash2((unsigned int *)tuple, 3, ((tuple->dport << 16) | tuple->proto));

    return ((unsigned long long)hash * mask) >> 32;
}

static void insert_hashtable(int dir, struct match_tuple *tuple, struct match_table *table)
{
    unsigned int hash;
    struct tuple_info t;
    memset(&t, 0, sizeof(t));
    t.sport = tuple->sport;
    t.dport = tuple->dport;
    t.proto = tuple->proto;
    if (dir == 0)
        t.saddr = tuple->addr;
    else
        t.daddr = tuple->addr;
    
    if (tuple->addr != 0 && tuple->sport != 0 && tuple->dport != 0)
    {
        hash = mkhash_tuple(&t, HASHTABLE_NUM_ABC);//printk("INSERT abc hash[%d]\n", hash);
        hlist_add_head(&tuple->hnode, &table->ht_abc[hash]);
        return ;
    }
    
    if (tuple->addr != 0 && tuple->sport != 0)
    {
        hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("INSERT abx hash[%d]\n", hash);
        hlist_add_head(&tuple->hnode, &table->ht_abx[hash]);
        return ;
    }
    
    if (tuple->addr != 0 && tuple->dport != 0)
    {
        hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("INSERT axc hash[%d]\n", hash);
        hlist_add_head(&tuple->hnode, &table->ht_axc[hash]);
        return ;
    }
    
    if (tuple->sport != 0 && tuple->dport != 0)
    {
        hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("INSERT xbc hash[%d]\n", hash);
        hlist_add_head(&tuple->hnode, &table->ht_xbc[hash]);
        return ;
    }
    
    if (tuple->addr != 0)
    {
        hash = mkhash_addr(tuple->addr, HASHTABLE_NUM_ADDR);//printk("INSERT axx hash[%d]\n", hash);
        hlist_add_head(&tuple->hnode, &table->ht_addr[hash]);
        return ;
    }
    
    if (tuple->sport != 0)
    {
        hlist_add_head(&tuple->hnode, &table->ht_srcp[tuple->sport]);
	   //  hash = mkhash_addr(tuple->sport, HASHTABLE_NUM_PORT);//printk("INSERT xbx hash[%d]\n", hash);
       //  hlist_add_head(&tuple->hnode, &table->ht_srcp[hash]);
        return ;
    }
    
    if (tuple->dport != 0)
    {
        hlist_add_head(&tuple->hnode, &table->ht_dstp[tuple->dport]);
		//hash = mkhash_addr(tuple->dport, HASHTABLE_NUM_PORT);//printk("INSERT xxc hash[%d]\n", hash);
        //hlist_add_head(&tuple->hnode, &table->ht_dstp[hash]);
        return ;
    }
	
    table->xxx = tuple;
}



int match_sys_kmalloc(struct match_table *mt)
{
	mt->ht_abc = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_ABC, GFP_ATOMIC);
	printk("size[%d]MB\n", sizeof(struct hlist_head) * 2);
	if (mt->ht_abc == NULL)
	{
		printk("the mt->ht_abc kmalloc was failed!\n");
		return -1;
	}
	
	mt->ht_abx = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_ABX, GFP_ATOMIC);
	if (mt->ht_abx == NULL)
	{
		printk("the mt->ht_abx kmalloc was failed!\n");	
		FREE_MT(mt->ht_abc);
		return -1;
	}

	mt->ht_axc = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_ABX, GFP_ATOMIC);
	if (mt->ht_axc == NULL)
	{
		printk("the mt->ht->axc kmalloc was failed!\n");
		FREE_MT(mt->ht_abc);
		FREE_MT(mt->ht_abx);
		return -1;
	}

	mt->ht_xbc = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_ABX, GFP_ATOMIC);
	if (mt->ht_xbc == NULL)
	{
		printk("the mt->ht_xbc kmalloc was failed!\n");
		FREE_MT(mt->ht_abc);
		FREE_MT(mt->ht_abx);
		FREE_MT(mt->ht_axc);
		return -1;
	}

	mt->ht_addr = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_ADDR, GFP_ATOMIC);
	if (mt->ht_addr == NULL)
	{
		printk("the mt->ht_addr kmalloc was failed!\n");
		FREE_MT(mt->ht_abc);
		FREE_MT(mt->ht_abx);
		FREE_MT(mt->ht_axc);
		FREE_MT(mt->ht_xbc);
		return -1;

	}

	mt->ht_srcp = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_PORT, GFP_ATOMIC);
	if (mt->ht_srcp == NULL)
	{
		printk("the mt->ht_srcp kmalloc was failed!\n");
		FREE_MT(mt->ht_abc);
		FREE_MT(mt->ht_abx);
		FREE_MT(mt->ht_axc);
		FREE_MT(mt->ht_xbc);
		FREE_MT(mt->ht_addr);
		return -1;
	}

	mt->ht_dstp = kmalloc(sizeof(struct hlist_head) * HASHTABLE_NUM_PORT, GFP_ATOMIC);
	if (mt->ht_dstp == NULL)
	{
		printk("the mt->ht_dstp kmalloc was failed!\n");
		FREE_MT(mt->ht_abc);
		FREE_MT(mt->ht_abx);
		FREE_MT(mt->ht_axc);
		FREE_MT(mt->ht_xbc);
		FREE_MT(mt->ht_addr);
		FREE_MT(mt->ht_srcp);
		return -1;
	}
	mt->xxx = kmalloc(sizeof(struct match_tuple), GFP_ATOMIC);
	return 0;
}

void match_sys_free(struct match_table *mt)
{
	FREE_MT(mt->ht_abc);
	FREE_MT(mt->ht_abx);
	FREE_MT(mt->ht_axc);
	FREE_MT(mt->ht_xbc);
	FREE_MT(mt->ht_addr);
	FREE_MT(mt->ht_srcp);
	FREE_MT(mt->ht_dstp);
}


////////////////////////////////////////////////////////////
// export function


int match_sys_init(void)
{
	mt_in_array_seg = NULL;
	mt_ot_array_seg = NULL;
	in_array_seg = NULL;
	ot_array_seg = NULL;
	mt_in_array_addr = NULL;
	mt_ot_array_addr = NULL;

    mt_in_tcp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);

    if (mt_in_tcp == NULL)
    {
        printk("the mt_in_tcp kmalloc was failed!\n");
        return -1;
    }
	if (match_sys_kmalloc(mt_in_tcp) == -1)
	{
		printk("the hash_table of mt_in_tcp kmalloc was failed!\n");
		FREE_MT(mt_in_tcp);
		return -1;
	}

    mt_ot_tcp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);
    if (mt_ot_tcp == NULL)
    {
        printk("the mt_ot_tcp kmalloc was failed!\n");
		FREE_MT_ALL(mt_in_tcp);
        return -1;
    }
	if (match_sys_kmalloc(mt_ot_tcp) == -1)
	{
		printk("the hash_table of mt_ot_tcp kmalloc was failed!\n");
		FREE_MT_ALL(mt_in_tcp);
		FREE_MT(mt_ot_tcp);
		return -1;
	}

    mt_in_udp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);
    if (mt_in_udp == NULL)
    {
        printk("the mt_in_udp kmalloc was failed!\n");
		FREE_MT_ALL(mt_in_tcp);
		FREE_MT_ALL(mt_ot_tcp);
        return -1;
    }
	if (match_sys_kmalloc(mt_in_udp) == -1)
	{
		printk("the hash_table of mt_in_udp kmalloc was failed!\n");
		FREE_MT_ALL(mt_in_tcp);
		FREE_MT_ALL(mt_ot_tcp);
		FREE_MT(mt_in_udp);
		return -1;
	}
    
    mt_ot_udp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);
    if (mt_ot_udp == NULL)
    {
        printk("the mt_ot_udp kmalloc was failed!\n");
        FREE_MT_ALL(mt_in_tcp);
		FREE_MT_ALL(mt_ot_tcp);
		FREE_MT_ALL(mt_in_udp);
        return -1;
    }
	if (match_sys_kmalloc(mt_ot_udp) == -1)
	{
		printk("the hash_table of mt_ot_udp kmalloc was failed!\n");
		FREE_MT_ALL(mt_in_tcp);
		FREE_MT_ALL(mt_ot_tcp);
		FREE_MT_ALL(mt_in_udp);
		FREE_MT(mt_ot_udp);
		return -1;
	}

    htable_init(mt_in_tcp);
    htable_init(mt_ot_tcp);
    htable_init(mt_in_udp);
    htable_init(mt_ot_udp);
    return 0;
}
EXPORT_SYMBOL(match_sys_init);

void match_sys_exit(void)
{
	int i = 0;	

	if (mt_in_array_addr)
	{
		for (i = 0; i < in_index; i++)
		{
			printk("free address [%d]: %#lx\n", i, (long unsigned int)mt_in_array_addr[i]);
			kfree(mt_in_array_addr[i]);
		}
		printk("free address mt_in_array_addr: %#lx\n", (long unsigned int)mt_in_array_addr);
		kfree(mt_in_array_addr);
	}

	if (mt_ot_array_addr)
	{
		for (i = 0; i < ot_index; i++)
		{
			printk("free address [%d]: %#lx\n", i, (long unsigned int)mt_ot_array_addr[i]);
			kfree(mt_ot_array_addr[i]);
		}
		printk("free address mt_ot_array_addr: %#lx\n", (long unsigned int)mt_ot_array_addr);
		kfree(mt_ot_array_addr);
	}

	FREE_MT(mt_in_array_seg);
	FREE_MT(mt_ot_array_seg);
	FREE_MT_ALL(mt_in_tcp);
	FREE_MT_ALL(mt_in_udp);
	FREE_MT_ALL(mt_ot_tcp);
	FREE_MT_ALL(mt_ot_udp);
}
EXPORT_SYMBOL(match_sys_exit);

int segment_load(struct segment_info *sinfo, int dir)
{
	int ret;
	struct match_segment* array;
	
	printk("the segment_info num[%d] direct[%d]\n", sinfo->count, sinfo->dirct);

	if (dir == 0) {
		insegcnt = sinfo->count;
		in_array_seg = kmalloc(sizeof(struct match_segment) * sinfo->count, GFP_ATOMIC);
		if (in_array_seg == NULL) {
			printk("the match_segment in_array kmalloc was failed!\n");
			return -1;
		}
	}
	if (dir == 1) {
		otsegcnt = sinfo->count;
		ot_array_seg = kmalloc((sizeof(struct match_segment)) * sinfo->count, GFP_ATOMIC);
		if (ot_array_seg == NULL) {
			printk("the match_segment ot_array kmalloc was failed!\n");
			return -1;
		}
	}
	
	array = (dir == 0 ? in_array_seg : ot_array_seg);
	ret = copy_from_user(array, sinfo->entries, sizeof(struct match_segment) * sinfo->count);
	if (ret != 0)
	{
		printk("the copy_from_user was failed\n");
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(segment_load);

int match_load(struct match_info *minfo, int dir)
{
    int ret, i, j, size, rest_count;
    struct match_table *mtcp, *mudp;
    struct match_tuple *mtuple;
	struct match_tuple **array_addr;
	struct match_segment *array;	

	array = (dir == 0 ? in_array_seg : ot_array_seg);

    size = minfo->count/MAX_COUNT + 1;
	rest_count = minfo->count%MAX_COUNT;

    printk("the match_info num[%d] direct[%d] size[%ld] array_addr[%d] rest_count[%d]\n", minfo->count, minfo->dirct, sizeof(struct match_tuple) * minfo->count, size, rest_count);
    
    mtcp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);
    if (mtcp == NULL)
    {
        printk("the match_table_tcp kmalloc was failed!\n");
		FREE_MT(array);
        return -1;
    }
	if (match_sys_kmalloc(mtcp) == -1)
	{
		printk("the hash_table of mtcp kmalloc was failed!\n");
		FREE_MT(array);
		FREE_MT(mtcp);
		return -1;
	}
    htable_init(mtcp);

    mudp = kmalloc(sizeof(struct match_table), GFP_ATOMIC);
    if (mudp == NULL)
    {
        printk("the match_table_udp kmalloc was failed!\n");
		FREE_MT(array);
		FREE_MT_ALL(mtcp);
        return -1;
    }
	if (match_sys_kmalloc(mudp) == -1)
	{
		printk("the hash_table of mudp kmalloc was failed!\n");
		FREE_MT(array);
		FREE_MT_ALL(mtcp);
		FREE_MT(mudp);
		return -1;
	}
    htable_init(mudp);

	array_addr = kmalloc(sizeof(struct match_tuple*) * size, GFP_ATOMIC);
	printk("kmalloc array[%d] at: %#lx \n", size, (long unsigned int)array_addr);
	if (array_addr == NULL)
	{
		printk("the match_tuple *array_addr kmalloc was failed!\n");
		FREE_MT(array);
		FREE_MT_ALL(mtcp);
		FREE_MT_ALL(mudp);
		return -1;
	}

	array_addr[size-1] = kmalloc(sizeof(struct match_tuple) * rest_count, GFP_ATOMIC);
	printk("kmalloc array[%d] size [%ld]\n", size-1, sizeof(struct match_tuple) * rest_count);
    if (array_addr[size-1] == NULL)
    {
        printk("the match_tuple array_addr[%d] size[%ld] kmalloc was failed!\n", size-1, sizeof(struct match_tuple) * rest_count);
		FREE_MT(array);
		FREE_MT_ALL(mtcp);	
		FREE_MT_ALL(mudp);
		kfree(array_addr);
        return -1;
    }	
	
	for(i=0; i<size-1; i++)
	{
		array_addr[i] = kmalloc(sizeof(struct match_tuple) * MAX_COUNT, GFP_ATOMIC);
		if(array_addr[i] == NULL)
		{
			printk("the match_tuple array_addr[%d] kmalloc was failed!\n", i);
			FREE_MT(array);
			FREE_MT_ALL(mtcp);
			FREE_MT_ALL(mudp);
			for(i = i-1; i >= 0; i--)
			{
				kfree(array_addr[i]);
			}
			kfree(array_addr[size-1]);
			kfree(array_addr);
       		return -1;
		}
	}

	ret = copy_from_user(array_addr[size-1], minfo->entries, sizeof(struct match_tuple)*rest_count);
	printk("copy %d items from minfo->entries: %#lx to array: %#lx \n", rest_count, (long unsigned int)minfo->entries, (long unsigned int)array_addr[size-1]);
    if (ret != 0)
    {
        printk("the copy_from_user was failed!\n");
        return -1;
    }

	for (i=0; i<size-1; i++)
	{
    	ret = copy_from_user(array_addr[i], minfo->entries + rest_count + i*MAX_COUNT, sizeof(struct match_tuple)*MAX_COUNT);
		printk("copy %d items from minfo->entries: %#lx to array: %#lx \n", MAX_COUNT, (long unsigned int)minfo->entries + rest_count + i*MAX_COUNT, (long unsigned int)array_addr[i]);
    	if (ret != 0)
    	{
        	printk("the copy_from_user was failed!\n");
        	return -1;
    	}
	}

	
	for (i = 0; i < rest_count; i++)
    {
		mtuple = &array_addr[size-1][i];
       	if (mtuple->proto == 6)
            insert_hashtable(dir, mtuple, mtcp);
        else if (mtuple->proto == 17)
        	insert_hashtable(dir, mtuple, mudp);
    }
	for (j = 0; j < size-1; j++)
	{
    	for (i = 0; i < MAX_COUNT; i++)
    	{
        	mtuple = &array_addr[j][i];
        	if (mtuple->proto == 6)
        	    insert_hashtable(dir, mtuple, mtcp);
        	else if (mtuple->proto == 17)
        	    insert_hashtable(dir, mtuple, mudp);
    	}
	}

    if (dir == 0)
    {
        spin_lock_bh(&in_spinlock);
		if (mt_in_array_addr)
		{
			for (i = 0; i < in_index; i++)
			{
				printk("free address [%d]: %#lx\n", i, (long unsigned int)mt_in_array_addr[i]);
				kfree(mt_in_array_addr[i]);
			}
			printk("free address mt_in_array_addr: %#lx\n", (long unsigned int)mt_in_array_addr);
			kfree(mt_in_array_addr);
		}
		in_index = size;
		mt_in_array_addr = array_addr;

		mt_insegcnt = insegcnt;
		if (mt_in_array_seg) kfree(mt_in_array_seg);
		mt_in_array_seg = in_array_seg;
 
        if (mt_in_tcp) FREE_MT_ALL(mt_in_tcp);
        mt_in_tcp = mtcp;
        if (mt_in_udp) FREE_MT_ALL(mt_in_udp);
        mt_in_udp = mudp;
        
        spin_unlock_bh(&in_spinlock);
    }
    else
    {
        spin_lock_bh(&ot_spinlock);
        if (mt_ot_array_addr)
		{
			for(i = 0; i < ot_index; i++)
			{
				printk("free address [%d]: %#lx\n", i, (long unsigned int)mt_ot_array_addr[i]);
				kfree(mt_ot_array_addr[i]);
			}
			printk("free address mt_in_array_addr: %#lx\n", (long unsigned int)mt_ot_array_addr);
			kfree(mt_ot_array_addr);
		}
		ot_index = size;
		mt_ot_array_addr = array_addr;
	
		mt_otsegcnt = otsegcnt;
		if (mt_ot_array_seg) kfree(mt_ot_array_seg);
		mt_ot_array_seg = ot_array_seg;
	
        if (mt_ot_tcp) FREE_MT_ALL(mt_ot_tcp);
        mt_ot_tcp = mtcp;
        if (mt_ot_udp) FREE_MT_ALL(mt_ot_udp);
        mt_ot_udp = mudp;
        
        spin_unlock_bh(&ot_spinlock);
    }
	return 0;
}
EXPORT_SYMBOL(match_load);

unsigned int match_rule_in(struct tuple_info *tuple)
{
    unsigned int action = NF_ACCEPT;
	unsigned char flag = 0;
    struct tuple_info t;
    struct match_table *htab;
    unsigned int hash;
    struct match_tuple *node = NULL;
	struct hlist_node  *temp;
 //	struct list_head list;
//	struct match_segment first; 
//	struct match_segment *snode;
	int i = 0;
//	INIT_LIST_HEAD(&list); 
    spin_lock_bh(&in_spinlock);
    if (tuple->proto == 6)
        htab = mt_in_tcp;
    else
        htab = mt_in_udp;
    
    memset(&t, 0, sizeof(t));
    t.saddr = tuple->saddr;
    t.sport = tuple->sport;
    t.dport = tuple->dport;
    t.proto = tuple->proto;

	//addr,sport,dport
   	hash = mkhash_tuple(&t, HASHTABLE_NUM_ABC);//printk("IN abc hash[%d]\n", hash);
	hlist_for_each_entry(node, temp, &htab->ht_abc[hash], hnode)
	{
		if (node->addr == t.saddr && node->sport == t.sport && node->dport == t.dport)
       	{
			TYPE_CHECK_IN(1);
       	}
	}
	
    //addr,sport
    t.dport = 0;
    hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("IN abx hash[%d]\n", hash);
    hlist_for_each_entry(node, temp, &htab->ht_abx[hash], hnode)
	{
		if (node->addr == t.saddr && node->sport == t.sport)
       	{
			TYPE_CHECK_IN(2);
       	}
	}
    
	//addr,dport
	t.dport = tuple->dport;
	t.sport = 0;
	hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("IN axc hash[%d]\n", hash);
	hlist_for_each_entry(node, temp, &htab->ht_axc[hash], hnode)
	{
		if (node->addr == t.saddr && node->dport == t.dport)
        {
			TYPE_CHECK_IN(3);
		}	
	}
    
	//sport,dport
	t.saddr = 0;
	t.sport = tuple->sport;
	hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("IN xbc hash[%d]\n", hash);
	hlist_for_each_entry(node, temp, &htab->ht_xbc[hash], hnode)
	{
		if (node->sport == t.sport && node->dport == t.dport)
        {
			TYPE_CHECK_IN(4);
        }
	}
    
	//addr
    hash = mkhash_addr(tuple->saddr, HASHTABLE_NUM_ADDR);//printk("IN axx hash[%d]\n", hash);
    hlist_for_each_entry(node, temp, &htab->ht_addr[hash], hnode)
	{
		if (node->addr == tuple->saddr)
        {
			TYPE_CHECK_IN(5);
       	}
	}

	for (i = 0; i < mt_insegcnt; i++)
	{
		if (mt_in_array_seg[i].mask == (tuple->saddr & htonl(0XFFFFFFFF << (32 - mt_in_array_seg[i].bits))))
		{
			//addr,sport,dport
			t.saddr = mt_in_array_seg[i].mask; 
   			hash = mkhash_tuple(&t, HASHTABLE_NUM_ABC);//printk("IN abc hash[%d]\n", hash);
			hlist_for_each_entry(node, temp, &htab->ht_abc[hash], hnode)
			{
				if (node->addr == t.saddr && node->sport == t.sport && node->dport == t.dport)
       			{
					TYPE_CHECK_IN(6);
       			}
			}
	
    		//addr,sport
    		t.dport = 0;
    		hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("IN abx hash[%d]\n", hash);
    		hlist_for_each_entry(node, temp, &htab->ht_abx[hash], hnode)
			{
				if (node->addr == t.saddr && node->sport == t.sport)
       			{
					TYPE_CHECK_IN(7);
				}
			}
    		
			//addr,dport
			t.dport = tuple->dport;
			t.sport = 0;
			hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);//printk("IN axc hash[%d]\n", hash);
			hlist_for_each_entry(node, temp, &htab->ht_axc[hash], hnode)
			{
				if (node->addr == t.saddr && node->dport == t.dport)
        		{
					TYPE_CHECK_IN(8);
				}	
			}
    
    		//addr
    		hash = mkhash_addr(t.saddr, HASHTABLE_NUM_ADDR);//printk("IN axx hash[%d]\n", hash);
    		hlist_for_each_entry(node, temp, &htab->ht_addr[hash], hnode)
			{
				if (node->addr == t.saddr)
        		{
					TYPE_CHECK_IN(9);
       			}
			}
		}
    }
    
	//sport
	//hash = mkhash_addr(tuple->sport, HASHTABLE_NUM_PORT);
    hlist_for_each_entry(node, temp, &htab->ht_srcp[tuple->sport], hnode)
	{
		if (node->sport == tuple->sport)
        {
			TYPE_CHECK_IN(10);
        }
	}

	//dport
    //hash = mkhash_addr(tuple->dport, HASHTABLE_NUM_PORT);
    hlist_for_each_entry(node, temp, &htab->ht_dstp[tuple->dport], hnode)
	{
		if (node->dport == tuple->dport)
        {
			TYPE_CHECK_IN(11);
        }
	}
    if (htab->xxx != NULL)
	{
        action = htab->xxx->action;
		goto out_action;
	}

	spin_unlock_bh(&in_spinlock);
	if(flag && (!action))
		send_to_user(tuple, NF_TEST);
	return action;        
out_action:
    spin_unlock_bh(&in_spinlock);
	if((flag != 0) && (!action))
	{
		send_to_user(tuple, NF_TEST);
	}
    send_to_user(tuple, action);
    return action;
}
EXPORT_SYMBOL(match_rule_in);

unsigned int match_rule_out(struct tuple_info *tuple)
{
    unsigned int hash;
	unsigned char flag = 0;
    unsigned int action = NF_ACCEPT;
    struct tuple_info t;
    struct match_table *htab;
    struct match_tuple *node = NULL;
	struct hlist_node  *temp;
	int i = 0;
	
	//do_gettimeofday(&start);
    
    spin_lock_bh(&ot_spinlock);
    if (tuple->proto == 6)
        htab = mt_ot_tcp;
    else
        htab = mt_ot_udp;
    
    memset(&t, 0, sizeof(t));
    t.daddr = tuple->daddr;
    t.sport = tuple->sport;
    t.dport = tuple->dport;
    t.proto = tuple->proto;
    hash = mkhash_tuple(&t, HASHTABLE_NUM_ABC);
	hlist_for_each_entry(node, temp, &htab->ht_abc[hash], hnode)
	{
		if (node->addr == t.daddr && node->sport == t.sport && node->dport == t.dport)
        {
			TYPE_CHECK_OT(1);
        }
	}
    
    t.dport = 0;
    hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);
    hlist_for_each_entry(node, temp, &htab->ht_abx[hash], hnode)
	{
		if (node->addr == t.daddr && node->sport == t.sport)
       	{
			TYPE_CHECK_OT(2);
		}
	}
    
    t.dport = tuple->dport;
    t.sport = 0;
    hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);
    hlist_for_each_entry(node, temp, &htab->ht_axc[hash], hnode)
	{
		if (node->addr == t.daddr && node->dport == t.dport)
        {
			TYPE_CHECK_OT(3);
        }
	}
    
    t.daddr = 0;
    t.sport = tuple->sport;
    hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);
	hlist_for_each_entry(node, temp, &htab->ht_xbc[hash], hnode)
	{
		if (node->sport == t.sport && node->dport == t.dport)
        {	
			TYPE_CHECK_OT(4);	
        }
	}
    
    hash = mkhash_addr(tuple->daddr, HASHTABLE_NUM_ADDR);
    hlist_for_each_entry(node, temp, &htab->ht_addr[hash], hnode)
	{
		if (node->addr == tuple->daddr)
        {
			TYPE_CHECK_OT(5);
        }
	}	

	//segment
	//INIT_LIST_HEAD(&list);
	for (i = 0; i < mt_otsegcnt; i++)
	{
		if (mt_ot_array_seg[i].mask == (tuple->daddr & htonl(0XFFFFFFFF << (32 - mt_ot_array_seg[i].bits))))
		{	
			printk("tuple->addr[%d] match mask[%d] at mt_ot_array_seg[%d]\n", tuple->daddr, mt_ot_array_seg[i].mask, i);
			//list_add_tail(&mt_ot_array_seg[i].hnode, &list);
			t.daddr = mt_ot_array_seg[i].mask;
    		hash = mkhash_tuple(&t, HASHTABLE_NUM_ABC);
			hlist_for_each_entry(node, temp, &htab->ht_abc[hash], hnode)
			{
				if (node->addr == t.daddr && node->sport == t.sport && node->dport == t.dport)
        		{
					TYPE_CHECK_OT(6);	
        		}
			}
    
    		t.dport = 0;
    		hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);
    		hlist_for_each_entry(node, temp, &htab->ht_abx[hash], hnode)
			{
				if (node->addr == t.daddr && node->sport == t.sport)
        		{
					TYPE_CHECK_OT(7);
        		}
			}
    
    		t.dport = tuple->dport;
    		t.sport = 0;
    		hash = mkhash_tuple(&t, HASHTABLE_NUM_ABX);
    		hlist_for_each_entry(node, temp, &htab->ht_axc[hash], hnode)
			{
				if (node->addr == t.daddr && node->dport == t.dport)
        		{
					TYPE_CHECK_OT(8);
        		}
			}
    
    		hash = mkhash_addr(mt_ot_array_seg[i].mask, HASHTABLE_NUM_ADDR);
    		hlist_for_each_entry(node, temp, &htab->ht_addr[hash], hnode)
			{
				if (node->addr == mt_ot_array_seg[i].mask)
        		{
					TYPE_CHECK_OT(9);
    	   		}
			}
		}
	 }
	 
	//hash = mkhash_addr(tuple->sport, HASHTABLE_NUM_PORT);   
    hlist_for_each_entry(node, temp, &htab->ht_srcp[tuple->sport], hnode)
	{
		if (node->sport == tuple->sport)
        {	
			TYPE_CHECK_OT(10);
        }
	}
    //hash = mkhash_addr(tuple->dport, HASHTABLE_NUM_PORT); 
    hlist_for_each_entry(node, temp, &htab->ht_dstp[tuple->dport], hnode)
	{
		if (node->dport == tuple->dport)
		{
			TYPE_CHECK_OT(11);
        }
	}
    //printk("OUT not found match pattern [%s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", tuple->proto==6?"tcp":"udp", 
    //    STR_IP(tuple->saddr), ntohs(tuple->sport), STR_IP(tuple->daddr), ntohs(tuple->dport));
    if (htab->xxx != NULL)
	{
        action = htab->xxx->action;
	    goto out_action;
	}
	spin_unlock_bh(&ot_spinlock);
	if(flag && (!action))
		send_to_user(tuple, NF_TEST);
	return action;        
out_action:
    spin_unlock_bh(&ot_spinlock);
	if((flag != 0) && (!action))
	{
		send_to_user(tuple, NF_TEST);
	}
    send_to_user(tuple, action);
	//do_gettimeofday(&end);
	//timeuse = 1000000*(end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	//printk("%dus    ", timeuse);
    return action;
}
EXPORT_SYMBOL(match_rule_out);
