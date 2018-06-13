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
#include <asm-generic/rtc.h>/* Needed for using get_rtc_time function */
//#include <linux/time.h> /*Needed for func do_getimeofday function */
#include <linux/sched.h> /*Needed for schedule_timeout function */
//Needed for proc
#include <linux/types.h>
//#include <linux/fs.h>
#include <linux/proc_fs.h>/*Needed for copy_from_user*/
#include <linux/stat.h>
//#include <linux/string.h>
//#include <asm/uaccess.h>

MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");

#define PROC_NAME "driver/pdump_prot"




//main module
struct ethhdr *mac;
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct ethhdr *ether_header;
struct skbbf *skb_bf;
static struct nf_hook_ops nfhook;
//register callback func to hook point

//Needed for timestamp

//char *time_tmp;
static char *months[12] ={"Jan", "Feb", "Mar", "Apr", "May", "Jun",
"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};





///fs/proc/internal.h


static int proc_open(struct inode *node, struct file *fp)
{
        printk("open\n");
        return 1;
}

static ssize_t proc_read(struct file *fp, char *buf, size_t size, loff_t *off)
{
        printk("read\n");
        return size;
}


static ssize_t proc_write(struct file *fp, const char *buf, size_t size, loff_t *off)
{
        printk("write\n");
        return size;
}

static struct file_operations example_proc_fops = {
        .owner = THIS_MODULE,
        .open = proc_open,
        .read = proc_read,
        .write = proc_write,
};



//get timestamp
static void timestamp(void)
{
  struct rtc_time t;
  get_rtc_time(&t);

  //      strcat(time_tmp, months[t.tm_mon]);
  //      write_buf(time_tmp);
  printk("%s %d %d:%d:%d %d",
  months[t.tm_mon], t.tm_mday, (t.tm_hour + 9), t.tm_min,
  t.tm_sec, 2000 + (t.tm_year % 100));
}



//main modules

static unsigned int payload_dump(unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*))

  {
    ip = (struct iphdr *)ip_hdr(skb);

    if(!ip){
      printk(KERN_WARNING "[DEBUG]ip header hook failed ");
    }


    /*-------------UDP------------------*/


    if(ip->protocol == 17) {
      udp = (struct udphdr *)ipip_hdr(skb);

      if(ntohs(udp->source) == 53 || ntohs(udp->dest) == 53){

      }

    }

    /*--------------TCP-----------------*/


    if(ip->protocol == 6) {
      tcp = (struct tcphdr *)ipip_hdr(skb);


      if(ntohs(tcp->source) == 23 || ntohs(tcp->dest) == 23){
        printk(KERN_ALERT "----TELNET-------------\n");
        }
        if(ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80){
          printk(KERN_ALERT "----HTTP-------------\n");

        }
        if(ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443){
          printk(KERN_ALERT "----HTTPS-------------\n");
        }

      }

      return NF_ACCEPT;
    }



    static int __init init_main(void)
    {

      static struct proc_dir_entry *pdir_entry;

      nfhook.hook     = payload_dump;
      nfhook.hooknum  = 0;
      nfhook.pf       = PF_INET;
      nfhook.priority = NF_IP_PRI_FIRST;
      nf_register_hook(&nfhook);
      timestamp();
      pdir_entry = proc_create(PROC_NAME, S_IRUGO | S_IWUGO | S_IXUGO, NULL, &example_proc_fops);
      if(!pdir_entry){
        remove_proc_entry(PROC_NAME, NULL);
        return -ENOMEM;
      }
      printk("proc example loaded\n");
             return 0;
    }

    static void __exit cleanup_main(void)
    {
      nf_unregister_hook(&nfhook);
      printk("refused packetdump_mod");
      printk(KERN_INFO "%s\n", __FUNCTION__);
      remove_proc_entry(PROC_NAME, NULL);

    }

    module_init(init_main);
    module_exit(cleanup_main);
