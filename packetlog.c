// my linux kernel version is 4.4.0 v127
// android packet dump module



#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/string.h> /* Needed for strcat */
#include <linux/skbuff.h> /* Needed for skbuff struct */
#include <linux/netfilter.h> /* Needed for hook　function */
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h> /* Needed for ip header */
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>
#include <linux/vfs.h>
#include <linux/namei.h>  /* Needed for path_lookup */
#include <linux/fs.h> /* Needed for  */
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/path.h> /* Needed for  */
#include <linux/mount.h> /* Needed for kern_path */

#include <linux/sched.h> /*Needed for schedule_timeout function */
#include <linux/version.h>/*Needed for version witching */
#include <linux/types.h>
#include <linux/proc_fs.h>

#define MODULE_NAME "Packetdump"
#define PROC_NAME "packetdump_mod"



MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");

//main module
struct ethhdr *mac;
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct ethhdr *ether_header;
struct skbbf *skb_bf;
struct net *net;

//register callback func to hook point
static struct nf_hook_ops nfhook;


//main modules

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))

//main modules
//refused static
unsigned int payload_dump(unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*))
  #else
  unsigned int payload_dump(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
  )
  #endif
  {



    return NF_ACCEPT;
  }

  static int __init init_main(void)
  {

    nfhook.hook     = payload_dump;
    nfhook.hooknum  = 0;
    nfhook.pf       = PF_INET;
    nfhook.priority = NF_IP_PRI_FIRST;
    #if (LINUX_VERSION_CODE == KERNEL_VERSION(4,4,0))
    nf_register_hook(&nfhook);
    #endif

    #if (LINUX_VERSION_CODE > KERNEL_VERSION(4,14,0))
    nf_register_net_hook(net, &nfhook);
    #endif

    printk("insmod packetmod.ko");


    return 0;
  }

  static void __exit cleanup_main(void)
  {


    #if (LINUX_VERSION_CODE == KERNEL_VERSION(4,4,0))
    nf_unregister_hook(&nfhook);
    #endif
    #if (LINUX_VERSION_CODE > KERNEL_VERSION(4,14,0))
    nf_unregister_net_hook(net, &nfhook);
    #endif


    printk("refused packetdump_mod");

  }

  module_init(init_main);
  module_exit(cleanup_main);
