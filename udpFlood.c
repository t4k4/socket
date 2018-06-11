#include <stdio.h>
#include <stdlib.h>
#include <limits.h> /* for UINT_MAX and USHRT_MAX */
#include <string.h>
#include <time.h>

#include <getopt.h> /* for command line options */
#include <sys/socket.h> /* for socket */
#include <sys/ioctl.h> /* for ioctl: binding socket to assigned interface */
#include <net/ethernet.h> /* for ether_header */
#include <netinet/ip.h> /* for iphdr */
#include <netinet/udp.h> /* for udphdr */
#include <linux/if.h> /* for IFNAMSIZ and ifreq */
#include <linux/if_packet.h> /* for sockaddr_ll */
#include <linux/sockios.h> /* for SIOCGIFINDEX */

#define random(x) (rand()%(x))
#define ETHER_TYPE ETHERTYPE_IP

#define DEF_INTERFACE "eth0"
#define BUFSIZE 1500


/* function declarations */
void construct_packet(struct sockaddr_ll * socket_address, uint8_t sendbuf[], 
    uint8_t src_mac[], uint8_t dst_mac[], /* ethernet header */
    uint8_t ttl, uint32_t *saddr, uint32_t *daddr, /* ip header*/ 
    uint16_t *sport, uint16_t *dport); /* udp header*/
unsigned short csum(unsigned short *buf, int nwords);

uint8_t * randomMAC(void);
uint32_t randomIP(void);
uint16_t randomPORT(void);

/* gateway MAC address */
uint8_t dst_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static void print_usage(const char * progname)
{
    printf("usage: %s [OPTION] destination_ip\n"
            "options:\n\t"
                "[-i device]\n\t"
                "[-a source ip addresss]\n\t"
                "[-t ttl]\n\t"
                "[-s source port]\n\t"
                "[-d destination port]\n", progname);
    return ;
}


int main(int argc, char *argv[]) 
{
    init_daemon();
    srand(time(NULL));
    uint8_t ttl = 64;
    uint32_t saddr = 0, daddr = 0;
    uint16_t sport = randomPORT(), dport = randomPORT();
    char ifname[IFNAMSIZ] = DEF_INTERFACE;;

    /* get cmd options */
    if(argc < 2){
        print_usage(argv[0]);
        return 1;
    }
        
    int opt;
    int option_index = 0;
    char * string = "i:a:t:s:d:";

    while((opt = getopt(argc, argv, string)) != -1){
        switch(opt){
            case 'i': 
                strcpy(ifname, optarg); 
                break;
            case 'a':
                saddr = inet_addr(optarg);
                break;
            case 't':
                ttl = (uint8_t)str2int(optarg);
                break;
            case 's':
                sport = htons((uint16_t)str2int(optarg));
                break;
            case 'd':
                dport = htons((uint16_t)str2int(optarg));
                break;
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    daddr = inet_addr(argv[argc-1]);
    
    if(!saddr || !daddr) {
        print_usage(argv[0]);
        exit(1);
    }


    /* generate random source mac address */
    uint8_t * src_mac = randomMAC();

    /* open socket */
    int sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0){
        perror("socket");
        exit(1);
    }

    /* bindsock to device interface */
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
        perror("bind sock to device");
        close(sockfd);
        exit(1);
    } 


    struct sockaddr_ll socket_address;
    /* index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* address length */
    socket_address.sll_halen = ETH_ALEN;
    /* destination mac */
    memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);


    /* define sendbuf */
    uint8_t sendbuf[BUFSIZE];
    /* construct packet */
    construct_packet(&socket_address, sendbuf, 
                    src_mac, dst_mac, /* ethernet */ 
                    ttl, &saddr, &daddr, /* ip */
                    &sport, &dport); /* udp */
    
    /* send */
    while(1){
        sendto(sockfd, sendbuf, BUFSIZE, 0, (struct sockaddr *)&socket_address,
                        sizeof(struct sockaddr_ll));
        sleep(1);
    }
    close(sockfd);
    free(src_mac);
    return 0;
}



void construct_packet(struct sockaddr_ll * socket_address, uint8_t sendbuf[], 
    uint8_t src_mac[], uint8_t dst_mac[], /* ethernet header */
    uint8_t ttl, uint32_t *saddr, uint32_t *daddr, /* ip header*/ 
    uint16_t *sport, uint16_t *dport) /* udp header*/
{
    uint16_t checksum;
    int tx_len = 0;

    /* initialize sendbuf */
    memset(sendbuf, 0, BUFSIZE);

    /* ethernet header */
    struct ether_header * eth_hdr = (struct ether_header *)sendbuf;
    memcpy(eth_hdr->ether_dhost, dst_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_IP); /* 0x0800 */

    tx_len += sizeof(struct ether_header);


    /* IP header */
    struct iphdr * ip = (struct iphdr *)(sendbuf+tx_len);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(BUFSIZE - tx_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = ttl;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = *saddr;
    ip->daddr = *daddr;

    /* calculate ip header checksum: including only ip header */
    checksum = csum((unsigned short *)ip, sizeof(struct iphdr)/2);
    /* update checksum */
    ip->check = checksum;
    tx_len += sizeof(struct iphdr);


    /* UDP header */
    struct udphdr * udp = (struct udphdr *)(sendbuf+tx_len);
    udp->source = *sport;
    udp->dest = *dport;
    udp->len = htons(BUFSIZE - tx_len);
    udp->check = 0;
   
    /* calculate udp checksum: including udp header and data*/
    checksum = csum((unsigned short *)udp, (BUFSIZE-tx_len)/2);
    /* update checksum */
    udp->check = checksum;
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

uint8_t * randomMAC(void)
{   
    uint8_t * mac = (uint8_t *)malloc(sizeof(uint8_t)*ETH_ALEN);
    memset(mac, 0, ETH_ALEN);
    int i = 1;
    for(; i<ETH_ALEN; ++i)        
        mac[i] = random(UCHAR_MAX);
    return mac;
}

uint32_t randomIP(void)
{
    /* randomly generate 32-bite IP address */
    return random(UINT_MAX);
}

uint16_t randomPORT(void)
{
    /* randomly generate 16-bit port number(cannot be zero) */
    return random(USHRT_MAX) + 1; 
}

int str2int(char * s)
{
    int i, n = strlen(s);
    int sum = 0;
    for(i=0; i<n; ++i)
        sum += sum * 10 + (s[i] - '0');
    return sum;
}
