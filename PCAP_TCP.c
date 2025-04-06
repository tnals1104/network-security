#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "myheader.h"

#define MAX_PAYLOAD_PRINT 32

void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷을 처리하는 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // IP 패킷인지 확인
    struct ethheader *eth = (struct ethheader *)packet;
    printf("\n=== Packet Captured ===\n");
    printf("Ethernet Header:\n");
    printf("   Src MAC: ");
    print_mac_address(eth->ether_shost);
    printf("\n   Dst MAC: ");
    print_mac_address(eth->ether_dhost);
    printf("\n");

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }
    
    // TCP 헤더인지 확인인
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    
    int ip_header_length = ip->iph_ihl * 4;
    
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }
    
    printf("IP Header:\n");
    printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));
    
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);
    
    int tcp_header_length = TH_OFF(tcp) * 4;
    
    printf("TCP Header:\n");
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));
    
    int total_ip_length = ntohs(ip->iph_len);
    int payload_length = total_ip_length - (ip_header_length + tcp_header_length);
    if (payload_length > 0) {
        const u_char *payload = packet + sizeof(struct ethheader) + ip_header_length + tcp_header_length;
        int print_length = (payload_length > MAX_PAYLOAD_PRINT) ? MAX_PAYLOAD_PRINT : payload_length;
        printf("Payload (%d bytes):\n   ", print_length);
        for (int i = 0; i < print_length; i++) {
            if (payload[i] >= 32 && payload[i] <= 126)
                printf("%c", payload[i]);
            else
                printf(".");
        }
        printf("\n");
    } else {
        printf("No Payload.\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 실시간으로 패킷을 캡처하기 위한 핸들 열기
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 설정 - TCP 패킷만 캡처하도록
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 패킷을 캡처하는 루프
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
