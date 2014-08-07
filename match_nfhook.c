#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/device.h>

#include "match_rule.h"
#include "ipc.h"
MODULE_LICENSE("GPL");


#define BIT_IP(x) ((unsigned char*)&(x))
#define STR_IP(x) BIT_IP(x)[0], BIT_IP(x)[1], BIT_IP(x)[2], BIT_IP(x)[3]

//////////////////////////////////////////////////////////
// hook

static struct nf_hook_ops ops_nfhk_li;
static struct nf_hook_ops ops_nfhk_lo;

static unsigned int hook_match_packet_li(
                unsigned int hooknum, 
                struct sk_buff *skb, 
                const struct net_device *in, 
                const struct net_device *ot, 
                int (*okfn)(struct sk_buff*))
{
    struct tuple_info t;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct iphdr  *iph;
    
    if (skb->len < sizeof(struct iphdr) || ip_hdrlen(skb) < sizeof(struct iphdr))
    {
        printk("hooknum : %d  skb->len : %d \n", hooknum,  skb->len);
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
        
    if (iph->protocol != 6 && iph->protocol != 17)
        return NF_ACCEPT;

    t.saddr = iph->saddr;
    t.daddr = iph->daddr;
    t.proto = iph->protocol;
    if (iph->protocol == 6)
    {
        tcph = (struct tcphdr*)((__u32 *)iph + iph->ihl);
        t.sport = tcph->source;
        t.dport = tcph->dest;
    }
    else
    {
        udph = (struct udphdr*)((__u32 *)iph + iph->ihl);
        t.sport = udph->source;
        t.dport = udph->dest;
    }
    
    return match_rule_in(&t);
	//return NF_ACCEPT;
}

static unsigned int hook_match_packet_lo(
                unsigned int hooknum, 
                struct sk_buff *skb, 
                const struct net_device *in, 
                const struct net_device *ot, 
                int (*okfn)(struct sk_buff*))
{
    struct tuple_info t;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct iphdr  *iph;
    
    if (skb->len < sizeof(struct iphdr) || ip_hdrlen(skb) < sizeof(struct iphdr))
    {
        printk("hooknum : %d  skb->len : %d \n", hooknum,  skb->len);
        return NF_ACCEPT;
    }
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (iph->protocol != 6 && iph->protocol != 17)
        return NF_ACCEPT;

    t.saddr = iph->saddr;
    t.daddr = iph->daddr;
    t.proto = iph->protocol;
    if (iph->protocol == 6)
    {
        tcph = (struct tcphdr*)((__u32 *)iph + iph->ihl);
        t.sport = tcph->source;
        t.dport = tcph->dest;
    }
    else
    {
        udph = (struct udphdr*)((__u32 *)iph + iph->ihl);
        t.sport = udph->source;
        t.dport = udph->dest;
    }
    
    return match_rule_out(&t);
	//return NF_ACCEPT;
}

//////////////////////////////////////////////////////////
// ioctrl

int g_MajorNumber = 0;
struct class *chrdev_class;

int match_fops_open(struct inode *fops_inode, struct file *fops_file)
{
	printk("match_fops_open called.\n");
    return 0;
}

int match_fops_close(struct inode *fops_inode, struct file *fops_file)
{
	printk("match_fops_close called.\n");
    return 0;
}

int match_fops_ioctl(struct inode *fops_inode, struct file *fops_file, unsigned int cmd, unsigned long arg)
{
	static int inret = 1, otret = 1;
	printk("match_fops_ioctl called.\n");
//	printk("command[%d]\n", cmd);
	if (_IOC_TYPE(cmd) != NF_IOC_MAGIC)
		return -EINVAL;
	if (_IOC_NR(cmd) > NF_IOC_MAXNR)
		return -EINVAL;

    switch (cmd)
    {
	case SET_MATCH_SEGMENT_IN :
        inret = segment_load((struct segment_info*)arg, 0);
        break;
    case SET_MATCH_SEGMENT_OUT:
        otret = segment_load((struct segment_info*)arg, 1);
        break;
	case SET_MATCH_PATTERN_IN :
		if (inret == 0)
		{
			match_load((struct match_info*)arg, 0);
			inret = 1;
		}
		break;
	case SET_MATCH_PATTERN_OUT:
		if (otret == 0)
		{
			match_load((struct match_info*)arg, 1);
			otret = 1;
		}
		break;
    }

    return 0;
}

struct file_operations match_fops = 
{
    .owner  = THIS_MODULE,
	.ioctl  = match_fops_ioctl,
    .open   = match_fops_open,
    .release= match_fops_close
};

static int fops_init_module(void)
{
    printk("Loading match_device utility driver.\n");

    g_MajorNumber = register_chrdev(g_MajorNumber, "MatchConfig", &match_fops);
    if (g_MajorNumber < 0)
    {
		printk("match_device utility driver cannot be registered!!!!.\n");
        return -1;
    }

    printk("match_device utility driver is registered with major:%d\n",g_MajorNumber);
    printk("USAGE:\n");
    printk("mknod /dev/MatchConfig c %d <minor>\n", g_MajorNumber);
    printk("with different minor numbers.\n\n");
    
    chrdev_class = class_create(THIS_MODULE, "MatchConfig");
    if (IS_ERR(chrdev_class))
    {
        printk("Err: failed in createing MatchConfig\n");
        return -1;
    }
    
    device_create(chrdev_class, NULL, MKDEV(g_MajorNumber, 0), NULL, "MatchConfig");
    return 0;
}    

static void fops_exit_module(void)
{
	printk("Unloading match_device utility driver.\n");
    device_destroy(chrdev_class, MKDEV(g_MajorNumber, 0));
    class_destroy(chrdev_class);
    unregister_chrdev(g_MajorNumber, "MatchConfig");
}

static int init_matchnf(void)
{
    if (match_sys_init() != 0)
    {
        printk("match system init was failed!\n");
        return -1;
    }

    if (netlink_init() != 0)
    {
	printk("netlink init was failed!\n");
    }
    
    fops_init_module();
    
    ops_nfhk_li.hook    = hook_match_packet_li;
    ops_nfhk_li.owner   = THIS_MODULE,
    ops_nfhk_li.hooknum = NF_INET_LOCAL_IN;
    ops_nfhk_li.pf      = PF_INET;
    ops_nfhk_li.priority= NF_IP_PRI_FIRST;

    if (nf_register_hook(&ops_nfhk_li) != 0)
    {
        printk("register LOCAL_IN hook was failed!\n");
        return -1;
    }

	ops_nfhk_lo.hook    = hook_match_packet_lo;
    ops_nfhk_li.owner   = THIS_MODULE,
    ops_nfhk_lo.hooknum = NF_INET_LOCAL_OUT;
    ops_nfhk_lo.pf      = PF_INET;
    ops_nfhk_lo.priority= NF_IP_PRI_FIRST;

    if (nf_register_hook(&ops_nfhk_lo) != 0)
    {
        printk("register LOCAL_OUT hook was failed!\n");
        return -1;
    }

    printk("Init init_matchnf!\n");
    return 0;
}

static void exit_matchnf(void)
{
	nf_unregister_hook(&ops_nfhk_li);
    nf_unregister_hook(&ops_nfhk_lo);
    
    fops_exit_module();
    match_sys_exit();
    netlink_exit();

	printk("Exit exit_matchnf!\n");
}

module_init(init_matchnf);
module_exit(exit_matchnf);
