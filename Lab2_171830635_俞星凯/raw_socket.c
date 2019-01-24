#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048
int main(int argc,char* argv[]){
	int sock_fd; 
	int proto;
	int type; 
	int n_read;
	char buffer[BUFFER_MAX];
	char *eth_head;
	char *ip_head;
	char *arp_head;
	unsigned char *p;
	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
		printf("error create raw socket\n");
		return -1;
	}
	while(1){
		n_read=recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read<42){
			printf("error when recv msg\n");
			return -1;
		}
		eth_head=buffer;
		p=eth_head;
		printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x==>%.2x:%02x:%02x:%02x:%02x:%02x\n",
			p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
		if(p[12]==8&&p[13]==0)
		{
			ip_head=eth_head+14;
			p=ip_head+12;
			printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",
				p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
			proto=(ip_head+9)[0];
			printf("Protocol:");
			switch(proto){
				case IPPROTO_ICMP:printf("icmp\n");break;
				case IPPROTO_IGMP:printf("igmp\n");break;
				case IPPROTO_IPIP:printf("ipip\n");break;
				case IPPROTO_TCP:printf("tcp\n");break;
				case IPPROTO_UDP:printf("udp\n");break;
				default:printf("Pls query yourself\n");
			}
		}
		else if(p[12]==8&&p[13]==6)
		{
			arp_head=eth_head+14;
			p=arp_head+14;
			printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",
				p[0],p[1],p[2],p[3],p[10],p[11],p[12],p[13]);
			printf("Protocol:arp\n");
		}
	}
	return -1;
}
