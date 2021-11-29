#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <sys/ioctl.h> 
#include <net/if.h>


#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define ETH_HLEN 14
#define TCPPROTO_HTTP 80
#define TCPPROTO_HTTPS 443

using namespace std;

#pragma pack(push, 1)
struct TcpForward{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
}tcpForward;
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpBackward{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
    char msg[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
}tcpBackward;
#pragma pack(pop)

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

Mac get_my_mac(char* dev)
{
	int fd;
	char* mac;

	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , dev , IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	mac = (char *)ifr.ifr_hwaddr.sa_data;
	sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);

	return Mac(mac);
}

uint16_t cal_checksum(void* pkt, int size)
{
    uint16_t * buf = (uint16_t *) pkt;
    unsigned int res = 0;

    while(size > 1)
    {
        res += *buf;
        buf++;
        size -= sizeof(uint16_t);
    }

    if(size) 
        res += *buf;
    
    while( res >> 16 )
        res = (res & 0xFFFF) + (res >> 16); //carray

    res = ~res;

    return (uint16_t(res));
}

uint16_t tcp_checksum(void* pkt, Pseudoheader pseudo)
{
    uint16_t pse = ~cal_checksum(&pseudo, sizeof(Pseudoheader));
    uint16_t tcp = ~cal_checksum(pkt, htons(pseudo.tcp_len));

    unsigned int res = pse + tcp;
    
    while( res >> 16 )
        res = (res & 0xFFFF) + (res >> 16); //carray
    
    res = ~res;

    return (uint16_t(res));
}

int main(int argc, char* argv[])
{
    if(argc!=3){
        usage();
        return -1;
    }

    string dev = argv[1];
    string pattern = argv[2];

    Mac mymac = get_my_mac(argv[1]);

    cout << "my mac : " << std::string(mymac) << endl;
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev.c_str(), errbuf);
		return -1;
	}

	while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }

        EthHdr * eth = (EthHdr *) packet;
        if(eth->type() != EthHdr::Ip4) continue;    // ipv4 check
        IpHdr * ip = (IpHdr *)(packet + ETH_HLEN);
        if(ip->protocol != IPPROTO_TCP) continue;   // tcp check
        
        uint32_t IP_HLEN = ip->hl() * 4;
        TcpHdr * tcp = (TcpHdr *)((char *)ip + IP_HLEN);
        if(tcp->dport() != TCPPROTO_HTTP && tcp->dport() != TCPPROTO_HTTPS) continue;

        uint32_t TCP_HLEN = tcp->th_off * 4;
        char *payload = (char *)((char*)tcp + TCP_HLEN);
        uint32_t payload_len = ip->tlen() - IP_HLEN - TCP_HLEN;

        // printf("src port : %u \n",ntohs(tcp->th_sport));
        // printf("dst port : %u \n",ntohs(tcp->th_dport));
        
        if( string(payload, payload_len).find(pattern) != string::npos){
            cout << "[*]Detect!" << endl;
            
            //forward
            tcpForward.ethHdr = *eth;
            tcpForward.ipHdr = *ip;
            tcpForward.tcpHdr = *tcp;

            tcpForward.ethHdr.smac_ = mymac;

            tcpForward.ipHdr.tot_len = htons(40);
            tcpForward.ipHdr.ttl = 128;
            tcpForward.ipHdr.check = 0;

            tcpForward.tcpHdr.th_off = 5;
            tcpForward.tcpHdr.th_flags = TH_RST | TH_ACK;
            tcpForward.tcpHdr.th_seq = htonl(ntohl(tcp->th_seq) + payload_len);
            tcpForward.tcpHdr.th_ack = tcp->th_ack;
            tcpForward.tcpHdr.th_sum = 0;

            //backward
            tcpBackward.ethHdr = *eth;
            tcpBackward.ipHdr = *ip;
            tcpBackward.tcpHdr = *tcp;

            tcpBackward.ethHdr.smac_ = mymac;
            tcpBackward.ethHdr.smac_ = eth->dmac_;

            tcpBackward.ipHdr.dip_ = ip->sip_;
            tcpBackward.ipHdr.sip_ = ip->dip_;
            tcpBackward.ipHdr.tot_len = htons(40 + 56);
            tcpBackward.ipHdr.ttl = 128;
            tcpBackward.ipHdr.check = 0;

            tcpBackward.tcpHdr.th_off = 5;
            tcpBackward.tcpHdr.th_sport = tcp->th_dport;
            tcpBackward.tcpHdr.th_dport = tcp->th_sport;
            tcpBackward.tcpHdr.th_flags = TH_FIN | TH_ACK;
            tcpBackward.tcpHdr.th_seq = tcp->th_ack;
            tcpBackward.tcpHdr.th_ack = htonl(htonl(tcp->th_seq) + payload_len);
            tcpBackward.tcpHdr.th_sum = 0;

            //ip checksum
            tcpForward.ipHdr.check = cal_checksum(&tcpForward.ipHdr, 20);
            tcpBackward.ipHdr.check = cal_checksum(&tcpBackward.ipHdr, 20);

            //set pseudo
            pseudoForward.dip = tcpForward.ipHdr.dip_;
            pseudoForward.sip = tcpForward.ipHdr.sip_;
            pseudoForward.protocol = IPPROTO_TCP;
            pseudoForward.tcp_len = htons(20);

            pseudoBackward.dip = tcpBackward.ipHdr.dip_;
            pseudoBackward.sip = tcpBackward.ipHdr.sip_;
            pseudoBackward.protocol = IPPROTO_TCP;
            pseudoBackward.tcp_len = htons(20 + 56);

            //tcp checksum
            tcpForward.tcpHdr.th_sum = tcp_checksum(&(tcpForward.tcpHdr), pseudoForward);
            tcpBackward.tcpHdr.th_sum = tcp_checksum(&(tcpBackward.tcpHdr), pseudoBackward);

            //pcap send
            int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&tcpForward), sizeof(tcpForward));
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&tcpBackward), sizeof(tcpBackward));
        }
    }
    pcap_close(handle);

    return 0;
}