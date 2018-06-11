#define _GNU_SOURCE /* for cpu affinity */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <getopt.h>
#include <unistd.h>
#include <sched.h> /* for sched_setaffinity and priority*/
#include <pthread.h> /* for multi-thread */
#include <omp.h> /* for parallel task */
#include <arpa/inet.h>
#include <sys/select.h> /* for select */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/ethernet.h> /* for ether_header */
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h> /*  for iphdr */
#include <linux/icmp.h> /* for icmphdr */
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sockios.h> /* for ioctl */

#define random(x) (rand()%(x))

#define BUFSIZE 1024

#define DEF_INTERFACE  "eth0"
#define START_IP     0xc0a80101 /* 192.168.1.1 */
#define END_IP       0xc0a801fe /* 192.168.1.254 */
#define START_TTL    1
#define END_TTL      3
#define TTL          0x80 /* ttl = 128 */

#define MAXHOPS      5

#define N_THREADS    2
#define CPU_IDX      0



/* function declarations */
void fake_packet(int * tx_len, struct iphdr * ip, struct icmphdr * icmp, uint8_t * data,
    struct iphdr * rip, uint32_t * saddr);
unsigned short csum(unsigned short *buf, int nwords);
uint8_t * randomMAC(void);

uint8_t recvbuf[N_THREADS][BUFSIZE];
pthread_t sThread[N_THREADS];
int is_empty[N_THREADS];

char ifName[IFNAMSIZ] = DEF_INTERFACE;

void * sender(void * arg)
{
    int j = *((int *)arg); /* jth thread */
    uint8_t * src_mac = randomMAC();
    uint8_t dst_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; /* gateway MAC address */
    uint32_t fake_ips[MAXHOPS] = {
        (uint32_t)inet_addr("1.1.1.1"),
        (uint32_t)inet_addr("2.2.2.2")
    };
    /* open a raw socket */
    int sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) { 
        perror("socket");
        close(sockfd);
        exit(1);
    }

    /* get the index of the interface to send on */
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(1);
    }

    /* send through raw socket */
    /* destination address */
    struct sockaddr_ll socket_address;
    /* index of NIC */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* address length */
    socket_address.sll_halen = ETH_ALEN;
    /* destination MAC */
    memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);


    uint8_t sendbuf[BUFSIZE];
    int tx_len = 0;

    /* construct packet */
    /* initialize */
    memset(sendbuf, 0, BUFSIZE);

    /* ethernet header */
    struct ether_header * eth_hdr = (struct ether_header *)sendbuf;
    /* dst mac and src mac */
    memcpy(eth_hdr->ether_dhost, dst_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);
    free(src_mac);
    /* protocol type */
    eth_hdr->ether_type = htons(ETH_P_IP);
    tx_len = sizeof(struct ether_header);

    /* IP header */
    /* predefine */
    struct iphdr * ip = (struct iphdr *)(sendbuf + sizeof(struct ether_header));
    struct iphdr * rip = (struct iphdr *)(recvbuf[j] + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = htons(0x4000); /* flag and frag: don't frag */
    ip->ttl = TTL;

    /* ICMP header */
    struct icmphdr * icmp = (struct icmphdr *)(sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr));
    uint8_t * data = (uint8_t *)(sendbuf+sizeof(struct ether_header)
                        +sizeof(struct iphdr)+sizeof(struct icmphdr));
    /* send params */
    uint8_t ttl;

    while(1){
        if(is_empty[j]) continue;
        
        ttl = rip->ttl;

        if(ttl < START_TTL || !ip_in_range(&(rip->daddr)))
            is_empty[j] = 1;
        else if(ttl <= END_TTL){
            fake_packet(&tx_len, ip, icmp, data, rip, fake_ips+ttl-START_TTL);
            sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr *)&socket_address, 
                sizeof(struct sockaddr_ll));

            is_empty[j] = 1;
            tx_len = sizeof(struct ether_header);
            memset(sendbuf+tx_len+sizeof(struct iphdr), 0, BUFSIZE-tx_len-sizeof(struct iphdr));
        }

    }

    close(sockfd);
}

void print_usage(const char * progname){
    printf("usage: %s [-i interface]\n", progname);
    return ;
}

int main(int argc, char *argv[]) 
{
    //init_daemon();

    int j, nums[N_THREADS];
    for(j=0; j<N_THREADS; ++j){
        nums[j] = j;
        is_empty[j] = 1;
    }

    int opt, option_index = 0;
    char * string = "i:";
    while((opt = getopt(argc, argv, string)) != -1){
        switch(opt){
            case 'i':
                strcpy(ifName, optarg);
                break;
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    /* max number of RR(FIFO) priority */
    int maxprio = sched_get_priority_max(SCHED_FIFO);
    if(maxprio == -1){
        perror("sched_get_priority_max()");
        exit(1);
    }

    /* multi tasks */
    omp_set_num_threads(N_THREADS);
    #pragma omp parallel shared(nums) shared(maxprio)
    {
        int i = omp_get_thread_num();
        
        struct sched_param param;
        param.sched_priority = maxprio;

        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(CPU_IDX+i+1, &mask);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &mask); /* cpu affinity */
        pthread_attr_setschedpolicy(&attr, SCHED_FIFO); /* sched policy */
        pthread_attr_setschedparam(&attr, &param); /* sched priority */
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

        pthread_create(sThread+i, &attr, sender, (void *)&nums[i]);
    }


    /* set cpu affinity */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(CPU_IDX, &mask);
    sched_setaffinity(0, sizeof(cpu_set_t), &mask);

    /* set priority */
    struct sched_param param;
    param.sched_priority = maxprio;
    if(sched_setscheduler(getpid(), SCHED_FIFO, &param) == -1){
        perror("sched_setscheduler()");
        exit(1);
    }

    /* open listening socket */
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));
    if(sockfd < 0 ){
        perror("socket");
        exit(1);
    }

    /* bind sock to device */
    struct ifreq if_in;
    int sockopt;
    memset(&if_in, 0, sizeof(struct ifreq));

    /* set socket to promiscuous mode */
	strncpy(if_in.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(sockfd, SIOCGIFFLAGS, &if_in);
    if_in.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &if_in);

    /* allow socket to be reused */
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0){
        perror("socket reuse");
        close(sockfd);
        exit(1);
    }

    /* bind to device */
    if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) < 0){
        perror("bind sock to device");
        close(sockfd);
        exit(1);
    } 

    j = 0;
    int numbytes;
    fd_set fds;
    struct timeval timeout = {0, 0};

    while(1){  
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);

        switch(select(sockfd+1, &fds, NULL, NULL, &timeout)){
            case -1:
                exit(1); break;
            case 0:
                break;
            default:
                if(FD_ISSET(sockfd, &fds)){
                    numbytes = recvfrom(sockfd, recvbuf[j], BUFSIZE, 0, NULL, NULL);

                    if(recvbuf[j][sizeof(struct ether_header)+8] > END_TTL) continue;
                    else{
                        is_empty[j] = 0; j = (j + 1) % N_THREADS; 
                    }
                } 
        }
    }

    close(sockfd); 
    return 0;
}


void fake_packet(int * tx_len, struct iphdr * ip, struct icmphdr * icmp, uint8_t * data,
    struct iphdr * rip, uint32_t * saddr)
{
    
    uint16_t tol = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr);
    uint16_t checksum;
    struct tcphdr * rtcp = (struct tcphdr *)(rip + sizeof(struct iphdr));
    /* ip header */
    switch(rip->protocol){
        case IPPROTO_ICMP:
            tol += sizeof(struct icmphdr);
            break;
        case IPPROTO_UDP:
            tol += sizeof(struct udphdr);
            break;
        case IPPROTO_TCP:
            tol += rtcp->doff * 4;
            break;
        default:
            return;
    }

    /* ip header */
    ip->tot_len = htons(tol);
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0; /* initialize checksum */
    ip->saddr = *saddr;
    ip->daddr = rip->saddr;
    checksum = csum((unsigned short *)ip, sizeof(struct iphdr)/2);
    ip->check = checksum; /* update checksum */


    /* icmp header */
    icmp->type = ICMP_TIME_EXCEEDED;
    icmp->code = ICMP_EXC_TTL;
    icmp->checksum = 0; /* initialize checksum */
    /* copy data */
    memcpy(data, (uint8_t *)rip,
        tol-sizeof(struct iphdr)-sizeof(struct icmphdr));

    *tx_len += tol;

    checksum = csum((unsigned short *)icmp, (tol-sizeof(struct iphdr))/2);
    icmp->checksum = checksum; /* update checksum */
}

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int ip_in_range(uint32_t * addr)
{
    uint32_t s = ntohl(*addr);
    if(s >= START_IP && s <= END_IP)
        return 1;
    else return 0;
}

uint8_t * randomMAC(void)
{   
    uint8_t * mac = (uint8_t *)malloc(sizeof(uint8_t)*ETH_ALEN);
    memset(mac, 0, ETH_ALEN);
    int i = 1;
    for(; i<ETH_ALEN; ++i)        
        mac[i] = random(UCHAR_MAX);
    return mac;
}
