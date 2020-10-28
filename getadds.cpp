#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

int get_ip(char* ip, char* iface)
{
	int fd;
	struct ifreq ifr;
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0))==0){
        printf("socket error!\n");
        return -1;
    }

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFADDR, &ifr)!=0){
        printf("ioctl error!\n");
        return -1;
    }

	close(fd);
    
    strcpy(ip, inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));

	return 0;
}

int get_mac(char* mac, char* iface)
{
	int fd;
	struct ifreq ifr;
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0))==0){
        printf("socket error!\n");
        return -1;
    }

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr)!=0){
        printf("ioctl error!\n");
        return -1;
    }

	close(fd);
    
    uint8_t* mac_str = (uint8_t*)ifr.ifr_addr.sa_data;
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac_str[0], mac_str[1], mac_str[2], \
            mac_str[3], mac_str[4], mac_str[5]);

	return 0;
}
