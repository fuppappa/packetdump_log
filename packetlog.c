/*
 * my linux kernel version is 4.4.0 v127
 * target android hammerhead kernel version 3.3.0
 * android packet dump module
 */

/*
 * this module dump all packet
 * dump data export proc file (/drivers/pdump_prot)
 * Latest update 2018, 6, 20
 */

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/string.h> /* Needed for strcat */
#include <linux/vmalloc.h> /* Needed for vmalloc func */
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
#include <linux/proc_fs.h>/* Needed for copy_from_user */
#include <linux/stat.h>
//#include <linux/string.h>
//#include <asm/uaccess.h>

MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");


// this module is in production

#define buf_size PAGE_SIZE

#define buf_next(n) (((n) + 1) % buffer_size)

struct ring_buf{

  int queue[buffer_size];
  int head;
  int tail;
};

typedef struct ring_buf ring_t;

/***
this func is log_buffer init func
***/

static void buf_init(ring_t *q)
{
  q->head = 0;
  q->tail = 0;
}

/***
if buff is empty return 1
 not empty return 0
***/

int buf_emp(ring_t q)
{
  return(q.head == q.tail)
}



int buf_push(ring_t *q , int data)
{
  if(buffer_next(q->tail) == q->head)
  return -1

  q->queue[q->tail] = data;

  q->tail = buf_next(q->tail);

  return 0;
}






#define PROC_NAME "driver/pdump_prot"
#define MAX_FILE_LENGTH PAGE_SIZE
#define LOG_BUFFER_SIZE 16392
/* proc file entry */

// /fs/proc/internal.h lines-31
struct proc_dir_entry *proc_entry;

const char proc_buf[LOG_BUFFER_SIZE];
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


static int proc_open(struct inode *node, struct file *fp){
  printk("open\n");
  return 0;
}

static ssize_t proc_read(struct file *fp, char __user *buf, size_t size, loff_t *off)
{


/*  int buf_size;

  if(size < *proc_buf){
    buf_size = size;
  } else{
    buf_size = sizeof(proc_buf);
  }
  //strcpy(proc_buf, "tinnko");
  printk("[DEBUG]: kikenn ");
  memcpy(buf, proc_buf, buf_size);
  */printk(KERN_INFO "reading... buf=\n");
  return 0;
}


static long proc_write(struct file *fp, const char *buf, size_t size, loff_t *off)
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



int proc_create_entry(void) {

  int ret = 0;

  proc_entry = proc_create(PROC_NAME, S_IRUGO | S_IWUGO | S_IXUGO, NULL, &example_proc_fops);

  if (proc_entry == NULL) {

    ret = -ENOMEM;
    printk(KERN_INFO "[DEBUG]:mymodule_proc: Couldn't create proc entry\n");

  }
  return ret;

}

int proc_close(void){

  printk("proc_entry is succeed");
  remove_proc_entry(PROC_NAME, NULL);

  return 0;
}


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
    int err;
    nfhook.hook     = payload_dump;
    nfhook.hooknum  = 0;
    nfhook.pf       = PF_INET;
    nfhook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhook);
    timestamp();

    err = proc_create_entry();

    if(err == 0){
      printk("create proc entry is succeed\n");
    }
    return err;
  }

  static void __exit cleanup_main(void)
  {
    nf_unregister_hook(&nfhook);
    printk("refused packetdump_mod");
    printk(KERN_INFO "%s\n", __FUNCTION__);
    proc_close();

  }

  module_init(init_main);
  module_exit(cleanup_main);
