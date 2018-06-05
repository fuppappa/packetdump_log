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
//#include <linux/time.h> /*Needed for func timestamp*/



MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");

// my linux kernel version is 4.4.0


const char *filename = "/home/yfujeida/log/lkm/packetlog/log.txt";
mm_segment_t old_fs;
struct file *file;
struct ethhdr *mac;
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct ethhdr *ether_header;
struct skbbf *skb_bf;
static struct nf_hook_ops nfhook;



void file_open(void)
{

  old_fs = get_fs();
  set_fs(KERNEL_DS);


  // refused  S_IRWXU | S_IRWXG | S_IRWXO
  file = filp_open(filename, O_WRONLY | O_APPEND | O_LARGEFILE,0);


  if (IS_ERR(file)){
    printk(KERN_WARNING "[DEBUG]%d sys_write_log > file->f_pos is negative\n",IS_ERR(file) );
    return;
  }else{
    printk("we succeded getting file descriptor!!\n");
  }

}

void file_close(void)
{
  filp_close(file, NULL);
  printk("file closing is succeded\n");
  set_fs(old_fs);

}


//sprit function file_open file_close

void write_buf(char *buf)
{
  vfs_write(file, buf, strlen(buf), &file->f_pos);
  return;
}



//main modules

static unsigned int payload_dump(unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*))

  {
    char *tcp_pl;
    ip = (struct iphdr *)ip_hdr(skb);


    /*-------------UDP------------------*/


    if(ip->protocol == 17) {
      udp = (struct udphdr *)ipip_hdr(skb);

      if(ntohs(udp->source) == 53 || ntohs(udp->dest) == 53){
        printk(KERN_ALERT"----Domain Name System-------------\n");

      }

    }

    /*--------------TCP-----------------*/


    if(ip->protocol == 6) {
      tcp = (struct tcphdr *)ipip_hdr(skb);

      if(ntohs(tcp->source) == 23 || ntohs(tcp->dest) == 23){
        //  printk(KERN_ALERT "----TELNET-------------\n");


        //disputed point


        tcp_pl = (char *)tcp;
        tcp_pl =tcp_pl+tcp_hdrlen(skb);

        if(ntohs(tcp->source) == 23)
        {
          /*
          printk("telnet->:");
          printk("%s\n", tcp_pl);
          */
        }else{
          /*    printk("telnet<-:");
          printk("%s\n", tcp_pl);
          */ }

          //      printk("tail: %s", skb->head+skb->tail);
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
      nfhook.hook     = payload_dump;
      nfhook.hooknum  = 0;
      nfhook.pf       = PF_INET;
      nfhook.priority = NF_IP_PRI_FIRST;
      nf_register_hook(&nfhook);

      file_open();



      return 0;
    }

    static void __exit cleanup_main(void)
    {
      nf_unregister_hook(&nfhook);
      file_close();
      printk("refused protomodule");

    }

    module_init(init_main);
    module_exit(cleanup_main);
