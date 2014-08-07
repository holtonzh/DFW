#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <net/sock.h>

#include "match_rule.h"
#include "ipc.h"

MODULE_LICENSE("GPL");


DECLARE_MUTEX(receive_sem);
static struct sock *mysock;

struct 
{
	__u32 pid;
	rwlock_t lock;
} user_proc;


int send_to_user(struct tuple_info *tuple, int action)
{
	int ret = 0;
	int size;
	sk_buff_data_t old_tail;

	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct log_info *t;

	//头+数据部分对齐后的长度
	size = NLMSG_SPACE(sizeof(*t));
	skb = alloc_skb(size, GFP_ATOMIC);
	old_tail = skb->tail;

	
	nlh = NLMSG_PUT(skb, 0, 0, NL_MSG, size-sizeof(*nlh));
	t = NLMSG_DATA(nlh);
	memset(t, 0, sizeof(struct log_info));
	
	t->saddr = tuple->saddr;
	t->daddr = tuple->daddr;
        t->sport = tuple->sport;
        t->dport = tuple->dport;
        t->proto = tuple->proto;
	t->action = action;

   

        
	nlh->nlmsg_len = skb->tail - old_tail;
	NETLINK_CB(skb).pid = 0;	
	NETLINK_CB(skb).dst_group = 0;

	read_lock_bh(&user_proc.lock);	
	if(user_proc.pid != 0)
	{
		ret = netlink_unicast(mysock, skb, user_proc.pid, MSG_DONTWAIT);
	}
	read_unlock_bh(&user_proc.lock);
	return ret;
nlmsg_failure:
	if(skb)
	{
		kfree_skb(skb);
		printk("skb free success");
	}
	return -1;
}

EXPORT_SYMBOL(send_to_user);


static void my_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int len;

	//printk("%s,\n", __func__);

	nlh = nlmsg_hdr(skb);
	len = skb->len;
	

	while (NLMSG_OK(nlh, len))
	{
		//printk("%s, skb_len = %d \n", __func__, len);
	
	//write_lock_bh(&user_proc.pid);
	if (nlh->nlmsg_type == U_PID)
	{
		user_proc.pid = nlh->nlmsg_pid;
		//send_to_user(l);
		//send_to_user(l);
	}
	else if ((nlh->nlmsg_type == U_CLOSE) && (nlh->nlmsg_pid == user_proc.pid))
	{
		user_proc.pid = 0;
	}
	//write_unlock_bh(&user_proc.pid);
	netlink_ack(skb, nlh, 0);
	nlh = NLMSG_NEXT(nlh, len);
	}
	//printk("%s, end\n", __func__);
}

int netlink_init(void)
{	
	printk("%s, begin\n", __func__);
	rwlock_init(&user_proc.lock);
	mysock = netlink_kernel_create(&init_net, NL_MSG, 0, my_receive, NULL, THIS_MODULE);
	if(!mysock)
	{
		printk("%s, netlink_kernel_create failed \n", __func__);
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(netlink_init);

void netlink_exit(void)
{
	netlink_kernel_release(mysock);
	
}
EXPORT_SYMBOL(netlink_exit);
