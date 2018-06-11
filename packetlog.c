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
#include <linux/version.h>/*Needed for version witching */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
#include <asm-generic/rtc.h>/* Needed for using get_rtc_time function */
#endif

//#include <linux/time.h> /*Needed for func do_getimeofday function */
#include <linux/sched.h> /*Needed for schedule_timeout function */

MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");


//Needed for timestamp

//char *time_tmp;
static char *months[12] ={"Jan", "Feb", "Mar", "Apr", "May", "Jun",
"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

//Needed for file open, close, write
const char *filename = "/home/yfujeida/log/lkm/packetlog/log.txt";
mm_segment_t old_fs;
struct file *file;
//main module
struct ethhdr *mac;
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct ethhdr *ether_header;
//struct skbbf *skb_bf;

//register callback func to hook point
static struct nf_hook_ops nfhook;

int file_open(void);

void file_close(void);

void write_buf(char *buf);


#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))

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

#endif


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
    char *tcp_pl;
    unsigned int ipa;
    int i;
    char address[17];
//    char *tmp;
    //char *tmp;


    ip = (struct iphdr *)ip_hdr(skb);

    if(!ip){
      printk(KERN_WARNING "[DEBUG]ip header hook failed ");
    }



    //write_buf("source adress:");
    for (i=0;i<4;i++){

      ipa=(le32_to_cpu(ip->saddr)>>8*i)&0xff;

      //  sprintf(tmp_ip,"%d",ipa);
      //	strcat(address, tmp_ip);
      if(i<3){
        strcat(address, ".");

      }
    }

    //printk("%s\n", address);
    /*
    printk("\n");
    printk("%s", adress);


    printk("destination adress:(<-)");

    for (i=0;i<4;i++){

    ipa2=(le32_to_cpu(ip->daddr)>>8*i)&0xff;
    printk("%d", ipa2);
    if(i<3)
    printk(".");
  }
  printk("\n");
  printk("s_addr   :%x      \t\t",be32_to_cpu(ip->saddr));

  printk("d_addr :%x\n",be32_to_cpu(ip->daddr));
  */
  /*-------------UDP------------------*/


  if(ip->protocol == 17) {
    udp = (struct udphdr *)ipip_hdr(skb);
    /*
    printk(KERN_ALERT "\n---- UDP Header -------------------\n");
    printk("source port : %7u\t",ntohs(udp->source));
    printk("dest port   : %7u\t",ntohs(udp->dest));
    printk("UDP_packet_length    : %7u\t",ntohl(udp->len));
    printk("check     : %7u\n",ntohl(udp->check));
    */
    if(ntohs(udp->source) == 53 || ntohs(udp->dest) == 53){
      //  printk(KERN_ALERT"----Domain Name System-------------\n");
      /*	  int s[] = udp+(int)udp->len;

      printk("iiiii%d", *s);
      */

    }

  }

  /*--------------TCP-----------------*/


  if(ip->protocol == 6) {
    tcp = (struct tcphdr *)ipip_hdr(skb);
    //  sprintf(tmp,"%d", tcp->dest);
    //  strcat(tmp, ".");
    //  write_buf(tmp);
    /*
    printk(KERN_ALERT"\n---- TCP Header -------------------\n");
    printk("source port : %7u\t",ntohs(tcp->source));
    printk("dest port   : %7u\t",ntohs(tcp->dest));
    printk("sequence    : %7x\t",ntohl(tcp->seq));
    printk("ack seq     : %7x\n",ntohl(tcp->ack_seq));
    //4bit
    printk("data offset : %7u\n",tcp->doff);
    //1bit
    printk("frags       :");
    tcp->fin ? printk(" FIN") : 0 ;
    tcp->syn ? printk(" SYN") : 0 ;
    tcp->rst ? printk(" RST") : 0 ;
    tcp->psh ? printk(" PSH") : 0 ;
    tcp->ack ? printk(" ACK") : 0 ;
    tcp->urg ? printk(" URG") : 0 ;
    printk("\t");




    //limit size
    printk("window      : %7u\t",ntohs(tcp->window));
    //checksum
    printk("check       : 0x%x   \t",ntohs(tcp->check));
    //if contorol flag is urg only
    printk("urt_ptr     : %7u\n",tcp->urg_ptr);

    */
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
        //disputed point


        /*
        tcp = tcp+offset;
        while(tcp){

        printk("%s", tcp+i);
        i++;
      }

      tcp = tcp-offset;
      */
    }
    if(ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443){
      printk(KERN_ALERT "----HTTPS-------------\n");
    }
    /*
    printk(KERN_ALERT"\n---- skbuff -----------------------\n");
    printk("csum      :%3x\t",skb->csum);
    printk("ip_summed :%3x\t",skb->ip_summed);
    printk("priority  :%3x\t",skb->priority);
    printk("cloned    :%3x\t",skb->cloned);
    printk("nohdr     :%3x\n",skb->nohdr);
    printk("fclone    :%3x\t",skb->fclone);
    printk("peeked    :%3x\t",skb->peeked);
    printk("nf_trace  :%3x\t",skb->nf_trace);
    printk("protocol  :%3x\n",skb->protocol);
    printk("----end----\n\n\n");
    */
  }

  return NF_ACCEPT;
}

/* include linux/socket.h
line-163
#define AF_INET		2	 Internet IP Protocol
line-209
#define PF_INET AF_INET
*/


static int __init init_main(void)
{

  nfhook.hook     = payload_dump;
  nfhook.hooknum  = 0;
  nfhook.pf       = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
  nf_register_hook(&nfhook);
  #else
  nf_register_net_hook(&nfhook);
  #endif

  #if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
  timestamp();
  #endif

  file_open();
  //write_buf(&time_tmp);



  return 0;
}


// write_log modules

// function kern_path
/*
#include <linux/mount.h>
int kern_path(const char *name, unsigned int flags, struct path *path)
*/
int file_open(void)
{
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  struct path path;
  int err;
  // /fs/namei.c line-2118

  // /fs/namei.c line-1829
  err = kern_path(filename, LOOKUP_FOLLOW,&path);
  if(err){
    file = filp_open(filename, O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  }else{
    file = filp_open(filename, O_WRONLY | O_APPEND | O_LARGEFILE, 0);
    printk("we succeded getting file descriptor!!\n");
  }

  if (IS_ERR(file)){
    printk(KERN_WARNING "[DEBUG]%d sys_write_log > file->f_pos is negative\n",IS_ERR(file) );
    return -1;
  }
  return 0;
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
  /*  fs/read_write.c  function is defined ssize_t vfs_write(struct file *file,
  const char __user *buf, size_t count, loff_t *pos) {   */

  vfs_write(file, buf, strlen(buf), &file->f_pos);

  return;
}


static void __exit cleanup_main(void)
{

  #if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
  nf_unregister_hook(&nfhook);
  #else
  nf_unregister_net_hook(&nfhook);
  #endif


  file_close();
  printk("refused packetdump_mod");

}

module_init(init_main);
module_exit(cleanup_main);
