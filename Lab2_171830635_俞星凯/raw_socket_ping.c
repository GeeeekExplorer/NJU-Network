#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h> 
#define SEND_PACKET_NUM 32
#define BUFFER_SIZE 2048 

/*校验和算法*/
int cal_cksum(unsigned short *packet, int len)
{    
	int nleft = len;    
	int sum = 0;    
	unsigned short *w = packet;    
	unsigned short cksum = 0;   
	/*把ICMP报头二进制数据以2字节为单位累加起来*/   
	while (nleft > 1)    
	{       
		sum += *w++;       
		nleft -= 2;    
	}     
	/*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/        
	if (nleft == 1)    
	{            
	    *((unsigned char *)&cksum) = *((unsigned char *)w);        
		sum += cksum;    
	}     
	sum = (sum>>16) + (sum & 0xffff);    
	sum += (sum >> 16);    
	cksum= ~sum;     
	return cksum;
} 

/*两个timeval结构相减*/
void cal_interval(struct timeval *recv_time, struct timeval *send_time)
{    
	if ((recv_time->tv_usec -= send_time->tv_usec) < 0)    
	{       
		 recv_time->tv_sec -= 1;        
		 recv_time->tv_usec += 1000000;    
	}    
	recv_time->tv_sec -= send_time->tv_sec;
} 

/*设置ICMP报头*/
int pack(char *packet_buf, uint32_t packet_no)
{    
	struct icmp *icmp_st;    
	int data_size = 56;    
	int packet_size;         
	icmp_st = (struct icmp *)packet_buf;    
	icmp_st->icmp_type = ICMP_ECHO; //请求回送    
	icmp_st->icmp_code = 0;    
	icmp_st->icmp_cksum = 0;    
	icmp_st->icmp_seq = packet_no;    
	icmp_st->icmp_id = getpid();       
	gettimeofday((struct timeval *)icmp_st->icmp_data, NULL);     
	packet_size = 8 + data_size;    
	icmp_st->icmp_cksum = cal_cksum((unsigned short *)packet_buf, packet_size);
	return packet_size;
} 

/*发送ICMP报文*/
int send_packet(int socket_fd, struct sockaddr *addr, char *packet_buf, int packet_no)
{    
	int packet_size;     
	packet_size = pack(packet_buf, packet_no);    
	if ((packet_size = sendto(socket_fd, packet_buf, packet_size, 0, addr, sizeof(struct sockaddr_in))) == -1)    
	{        
		perror("sendto return -1");        
		return -1;   
	}    
	return 0; 
} 

/*剥去ICMP报头*/
int unpack(struct sockaddr_in *addr, char *packet_buf, int packet_size, struct timeval *recv_time, double *rtt ,unsigned int *ttl)
{    
	struct ip *ip_st;    
	struct icmp *icmp_st;    
	int ipheader;     
	ip_st = (struct ip *)packet_buf;    
	ipheader = ip_st->ip_hl << 2;    
	icmp_st = (struct icmp *)(packet_buf + ipheader);     
	packet_size -= ipheader;    
	if (packet_size < 8)    
	{    	
		printf( "recvfrom packet_size < 8!\n");        
		return -1;
	}     
	if ((icmp_st->icmp_type == ICMP_ECHOREPLY) && (icmp_st->icmp_id == getpid()))    
	{        
		cal_interval(recv_time, (struct timeval *)icmp_st->icmp_data);  //收到的时间与发送的时间        
		*rtt = recv_time->tv_sec * 1000.0 + recv_time->tv_usec / 1000.0;        
		*ttl = ip_st->ip_ttl;        
		printf("%d bytes from %s: icmp_seq = %u  ttl = %d  rtt = %.3lfms\n",               
			packet_size, inet_ntoa(addr->sin_addr), icmp_st->icmp_seq, ip_st->ip_ttl, *rtt);
		return 0;    
	}    
	else    
	{        
		printf( "unpack error! icmp_type is %d, icmp_id is %d\r\n", 
			(icmp_st->icmp_type == ICMP_ECHOREPLY), (icmp_st->icmp_id == getpid()));        
		return -1;    
	}
}  

/*接收所有ICMP报文*/
int recv_packet(int socket_fd, char *packet_buf, int *length, double *rtt, unsigned int *ttl)
{    
	int packet_size;    
	struct sockaddr_in addr;    
	struct timeval recv_time;    
	socklen_t size = sizeof(struct sockaddr_in);     
	if ((packet_size = recvfrom(socket_fd, packet_buf, *length, 0, (struct sockaddr *)&addr, &size)) == -1)    
	{    	
		printf( "recvfrom return -1!\n" );        
		return -1;    
	}      
	*length = packet_size;    
	gettimeofday(&recv_time, NULL);    
	if (unpack(&addr, packet_buf, packet_size, &recv_time, rtt, ttl) != 0)    
	{        
		return -1;    
	}    
	return 0;
}  

int main(int argc, char *argv[])
{    
	if (argc != 2)    
	{        
		fprintf(stderr, "Usage: %s [address]\n", argv[0]);        
		return 0;    
	}    
	unsigned long inaddr = 0;    
	struct sockaddr_in dest_addr;    
	struct hostent *host;    
	int socket_fd = -1;      
	int packet_size = 2048; 
	char send_pac[BUFFER_SIZE] = {0};    
	char recv_pac[BUFFER_SIZE] = {0};    
	double rtt;    
	unsigned int ttl, send_packet_cnt = 0, recv_packet_cnt = 0;;        
	dest_addr.sin_family = AF_INET;    
	if ((inaddr = inet_addr(argv[1])) == INADDR_NONE)  /*是主机名*/
	{        
		if ((host = gethostbyname(argv[1])) == NULL)         
		{            
			fprintf(stderr, "gethostbyname error.\n");            
			return -1;        
		}        
		memcpy((char *)&(dest_addr.sin_addr), host->h_addr, host->h_length);    
	}    
	else  /*是ip地址*/    
	{       
		dest_addr.sin_addr.s_addr = inaddr;    
	}     
	if((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)    
	{        
		perror("socket error\n");        
		return -1;    
	}     
	printf("Ping %s(%s): %d bytes of data in ICMP packets.\n",
		argv[1], inet_ntoa(dest_addr.sin_addr), 56);           
	int i;     
	for (i = 1; i <=SEND_PACKET_NUM; i++)    
	{        
		sleep(1);
		if (send_packet(socket_fd, (struct sockaddr *)&dest_addr, send_pac, i) == -1)        
		{            
			printf("send_packet error\n");            
			close(socket_fd);            
			return -1;        
		}        
		else        
		{            
			++send_packet_cnt;        
		}                
	    if (recv_packet(socket_fd, recv_pac, &packet_size, &rtt, &ttl) == -1)            
		{                
			printf("recv_packet error\n");            
		}            
		else            
		{                
			++recv_packet_cnt;            
		}                
	}    
	close(socket_fd);       
	printf("\n--- %s ping statistics ---\n", argv[1]);    
	printf("%d packets transmitted, %d received, %%%d packet loss\n",            
		send_packet_cnt, recv_packet_cnt, (((send_packet_cnt-recv_packet_cnt) * 100)/send_packet_cnt));     
	return 0; 
}
