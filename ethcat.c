/*
 * ethcat.c
 *
 *  Created on: Oct 18, 2016
 *     
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* */
#ifdef LINUX
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#endif

#ifdef WINDOWS
#include <windows.h>
#include <winsock2.h>
/*#include <netinet/in.h>*/
#define __INSIDE_MSYS__
#define IFNAMSIZ 16
#define ETH_ALEN 6
#define ETH_DATA_LEN 1500
#define ETH_FRAME_LEN 1514
#define ETH_HLEN 14
#endif

struct ifmap
{
	unsigned long mem_start;
	unsigned long mem_end;
	unsigned short base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
	/* 3 bytes spare */
};
struct ifreq
{
#define IFHWADDRLEN	6
#define	IFNAMSIZ	16
	union
	{
		char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	} ifr_ifrn;

	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		struct	sockaddr ifru_netmask;
		struct  sockaddr ifru_hwaddr;
		short	ifru_flags;
		int	ifru_ivalue;
		int	ifru_mtu;
		struct  ifmap ifru_map;
		char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
		char	ifru_newname[IFNAMSIZ];
		char *	ifru_data;
	} ifr_ifru;
};



/*
 1) check for arguments:
    arguments: -l <listen> -c <client> -s <smac> -d <dmac> -p <proto> -f <file>
    -i <eth interface>
 2) create eth_svr() function inputs: smac,dmac,proto,data
 3) create eth_cli() function inputs: smac,dmac,proto,data
 4) create bld_eth_packet() and fill data structure with supplied args
 5) create rx_eth()
 6) create tx_eth()
 7) read data from supplied file, fill eth buffer into frame
   fill buffer until it's equal to the max data length.
 8) send ethernet frame through raw socket
 9) Receive raw ethernet frame from supplied dest mac address
 10) until timer expires read data from frame, and write to file

*/

/*
 * ETH_ALEN = 6
 * ETH_FRAME_LEN = 1514
*/

/* ethernet protocols:
#define ETH_P_LOOP      0x0060
#define ETH_P_PUP       0x0200
#define ETH_P_PUPAT     0x0201
#define ETH_P_IP        0x0800
#define ETH_P_X25       0x0805
#define ETH_P_ARP       0x0806
#define ETH_P_BPQ       0x08FF
#define ETH_P_IEEEPUP   0x0a00
#define ETH_P_IEEEPUPAT 0x0a01
#define ETH_P_BATMAN    0x4305
#define ETH_P_DEC       0x6000
#define ETH_P_DNA_DL    0x6001
#define ETH_P_DNA_RC    0x6002
#define ETH_P_DNA_RT    0x6003
#define ETH_P_LAT       0x6004
#define ETH_P_DIAG      0x6005
#define ETH_P_CUST      0x6006
#define ETH_P_SCA       0x6007
#define ETH_P_TEB       0x6558
#define ETH_P_RARP      0x8035
#define ETH_P_ATALK     0x809B
#define ETH_P_AARP      0x80F3
#define ETH_P_8021Q     0x8100
#define ETH_P_IPX       0x8137
#define ETH_P_IPV6      0x86DD
#define ETH_P_PAUSE     0x8808
#define ETH_P_SLOW      0x8809
#define ETH_P_WCCP      0x883E
#define ETH_P_PPP_DISC  0x8863
#define ETH_P_PPP_SES   0x8864
#define ETH_P_MPLS_UC   0x8847
#define ETH_P_MPLS_MC   0x8848
#define ETH_P_ATMMPOA   0x884c
#define ETH_P_LINK_CTL  0x886c
#define ETH_P_ATMFATE   0x8884
#define ETH_P_PAE       0x888E
#define ETH_P_AOE       0x88A2
#define ETH_P_8021AD    0x88A8
#define ETH_P_802_EX1   0x88B5
#define ETH_P_TIPC      0x88CA
#define ETH_P_8021AH    0x88E7
#define ETH_P_MVRP      0x88F5
#define ETH_P_1588      0x88F7
#define ETH_P_FCOE      0x8906
#define ETH_P_TDLS      0x890D
#define ETH_P_FIP       0x8914
#define ETH_P_QINQ1     0x9100
#define ETH_P_QINQ2     0x9200
#define ETH_P_QINQ3     0x9300
#define ETH_P_EDSA      0xDADA
#define ETH_P_AF_IUCV   0xFBFB
#define ETH_P_802_3_MIN 0x0600
*/
struct ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	unsigned short h_proto;
};
struct eth_frm {
	struct
	{
		struct ethhdr header;
		unsigned char data[ETH_DATA_LEN];
	}field;
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
	unsigned short proto;
	unsigned char buffer[ETH_FRAME_LEN];
	char *ifc;
};

unsigned char new_mac[ETH_ALEN];

unsigned char *parse_mac(char *mac)
{
	sprintf(new_mac,"%s","FF:FF:FF:FF:FF:FF:FF");
	/* this function checks to see if it's a valid mac.
	 * there may be a better way to do this, but it will do
	 * for now.
	 */

	/* Separate char string into an unsigned bit string */
	if(strlen(mac)==17)
	{
		sscanf(mac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &new_mac[0], &new_mac[1], &new_mac[2], &new_mac[3], &new_mac[4], &new_mac[5]);
		return new_mac;
	}
	return new_mac;
}
/* send_eth() */
/* send_eth needs eth_frm structure
 *
 * 1) opens a socket
 * 2) gets var with interface name
 * 3) gets source mac addr
 * 4) gets dst mac addr
 * 5) gets msg data
 * 6) calls sendto() function
 * 7) returns error if failed
 */
/*int send_eth(struct eth_frm *tx_eth_frm);*/

int send_eth(struct eth_frm *tx_eth_frm)
{
	int s=-1; /* socket descriptor */
	struct ifreq intfc;
	int ifindex=-1;
	int data_len = strlen(tx_eth_frm->buffer);
	unsigned int frame_len = data_len + ETH_HLEN;
#ifdef LINUX
	if((s=socket(AF_PACKET, SOCK_RAW, htons(tx_eth_frm->proto)))<0)
	{
		perror("send_eth: socket");
		return -1;

	}
#endif
#ifdef WINDOWS
	if((s=socket(AF_UNSPEC,SOCK_RAW, htons(tx_eth_frm->proto)))<0)
	{
		perror("send_eth: socket");
		return -1;

	}
#endif
#ifdef LINUX
	strncpy(intfc.ifr_name, tx_eth_frm->ifc, IFNAMSIZ);
	if(ioctl(s,SIOCGIFINDEX,&intfc)<0)
	{
		perror("ioctl get interface index call");
		return -1;
	}
	ifindex=intfc.ifr_ifindex;
	if(ioctl(s,SIOCGIFHWADDR,&intfc)<0)
	{
		perror("ioctl get interface addr call");
		return -1;
	}
	memcpy(intfc.ifr_hwaddr.sa_data,tx_eth_frm->smac,ETH_ALEN);
	close(s);
	return 0;
#endif
	return -1;
}


int recv_eth(struct eth_frm *rx_eth_frm)
{
	return 0;
}

/* recv_eth() */


int main(int argc, char *argv[])
{
	int s=-1; /* socket descriptor */
	struct eth_frm eth;
	struct ifreq iface;
	int ifindex;
	int c;
	char *endptr;
	extern char *optarg;
	extern int optind;
	extern int optopt;
	int lflg = 0;
	int cflg = 0;
	int errflg = 0;
	int is_server=0;
	char *opt_proto;
	char *opt_file;

	  if(argc<11)
	  {
	   (void)fprintf(stderr, "usage: ethcat -l <listen> -c <client> -s <smac> -d <dmac> -p <proto> -f <file> -i <eth interface> \n");
	   exit(2);
	  }

	while((c=getopt(argc, argv, "lcs:d:p:f:i:")) != EOF)
	{
		switch(c)
		{
			case 'l':
				printf("l flag: %d\n",optopt);
				is_server++;
				break;
			case 'c':
				printf("client called %d\n",optopt);
				if(is_server)
				{
					printf("server flag and client flag cannot be called at the same time\n");
					errflg++;
				}
				break;
			case 's':
				printf("src mac: %s\n",optarg);
				if(strlen(optarg)==17)
				{
				   memcpy(eth.smac,parse_mac(optarg),ETH_ALEN);
				} else {
				   printf ("invalid source mac address\n");
				   exit(2);
				}
				break;
			case 'd':
				printf("dst mac: %s\n",optarg);
				if(strlen(optarg)==17)
				{
				   memcpy(eth.dmac,parse_mac(optarg),ETH_ALEN);
				} else {
					printf("invalid destination mac\n");
					exit(2);
				}
				break;
			case 'p':
				printf("protocol: %s\n",optarg);
				eth.proto=strtol(optarg,&endptr,16);
				break;
			case 'f':
				printf("filename: %s\n",optarg);
				break;
			case 'i':					/* get interface, check if it's valid */
				printf("interface: %s\n",optarg);		/* copy string to eth structure */
				eth.ifc=malloc(IFNAMSIZ);
				memcpy(eth.ifc,optarg,IFNAMSIZ);
				break;
				/*
			case '*':
				errflg++;
				break;
				*/
			default:
				break;
		}
	  if(errflg) {
	   fprintf(stderr, "usage: ethcat -l <listen> -c <client> -s <smac> -d <dmac> -p <proto> -f <file> -i <eth interface> \n");
	   exit(2);
	  }
	}
	 return 0;
}
/*free(eth.ifc);*/







