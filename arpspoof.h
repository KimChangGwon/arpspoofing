#include <stdint.h>
#include <pcap.h>
#include <net/ethernet.h>

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define NORMALPACKET 3
#define ARPOP_OFFSET 20

#define ETH_PROTOCOLTYPE_OFFSET 12
#define ETH_SRC_MAC_OFFSET 6
#define ETH_DST_MAC_OFFSET 0

#define SRC_IP_OFFSET 28
#define DST_IP_OFFSET 38

#define BROADCASTING_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"
#define UNKNOWN_MAC "\x00\x00\x00\x00\x00\x00"
#define MACADDR_LEN 6

#pragma pack(1)
struct arphdr{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    int8_t ar_hln;
    int8_t ar_pln;
    uint16_t ar_op;
};
#pragma pop()

#pragma pack(1)
struct ether_arp{
    struct arphdr ea_hdr;
    int8_t arp_sha[6];	//sender hardware address
    uint32_t arp_spa;	//sender protocol address
    int8_t arp_tha[6];	//target hardware address
    uint32_t arp_tpa;	//target protocol address
};
#pragma pop()

#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op


#pragma pack(1)
struct arp_packet{
    struct ether_header ether_header;
    struct ether_arp ether_arp;
};
#pragma pop()

void print_error(uint8_t * errorPoint, uint8_t * errorBuf);
void GetMyMac(uint8_t * MacAddr, uint8_t * interface);
void GetMyIP(uint32_t * myIP, uint8_t * interface);
void SendARP(pcap_t * packet_handle, uint8_t * srcMAC, uint8_t * dstMAC, uint32_t srcIP, uint8_t * dstIP, int ARPop);
uint32_t IsReply(const uint8_t * packet, uint32_t idstIP, uint8_t * dstMAC);
void make_ether_header(struct ether_header * ether_header, uint8_t * dest, uint8_t * source, uint16_t type);
void make_arp_header(struct ether_arp * ether_arp, uint8_t * sha, uint32_t spa, uint8_t * tha, uint32_t tpa, uint32_t op);
void dump(struct pcap_pkthdr * header, uint8_t * packet);
uint32_t IsBroadCasting(uint8_t * packet, uint8_t * senderIP, uint8_t * targetIP);
uint32_t IsNormalPacket(uint8_t * packet, uint8_t * AttackerMACAddr, uint8_t * SenderMACAddr);
void Maniupulation(uint8_t * packet, uint8_t * myMACAddr, uint8_t * TargetMACAddr);
