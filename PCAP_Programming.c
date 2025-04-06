#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; // Destination host address. dst MAC
    u_char  ether_shost[6]; // Source host address. src MAC
    u_short ether_type;     // protocol type (IP, ARP, RARP, etc)
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl : 4, //IP header length
        iph_ver : 4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};


/* TCP Header */
struct tcpheader {
    u_short tcp_sport; // Source Port
    u_short tcp_dport; // Destination Port
};

/*  */
void got_packet(u_char* args, const struct pcap_pkthdr* header,
    const u_char* packet)
{
    // Ethernet Header 파싱
    struct ethheader* eth = (struct ethheader*)packet;

    // MAC 형식에 맞게 Ethernet Header 정보 출력
    printf("*** Ethernet Header ***\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // ether_type이 IP일 때만 처리
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        // IP Header 파싱
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        // IP Header 정보 출력
        printf("*** IP Header ***\n");
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

        // TCP Protocol만 처리
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이는 4바이트 단위
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_header_len);

            // TCP Header 정보 출력
            printf("*** TCP Header ***\n");
            printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Destinarion Port: %d\n", ntohs(tcp->tcp_dport));

            /* Message 출력을 위한 코드 */
            
            // tcp header 길이. tcp header의 12번째 바이트(4)
            int tcp_header_len = ((packet[sizeof(struct ethheader) + ip_header_len + 12]) >> 4) * 4;

            // 헤더 길이(Ethernet Header + IP Header + TCP Header)
            int total_headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            // 전체 패킷 길이
            int total_packet_len = header->caplen;
            // 메시지 길이(전체 패킷 길이 - 헤더 길이)
            int message_len = total_packet_len - total_headers_size;

            // Message 출력
            if (message_len > 0) { // message가 존재할 때
                // 메시지는 전체 헤더 길이 이후부터 시작됨
                const u_char* message = packet + total_headers_size;
                printf("\n*** Application Data (%d bytes) ***\n", 64);

                // 16진수로 64byte만 출력
                for (int i = 0; i < 64; i++) {
                    printf("%02x ", message[i]); // Hex
                    // 16바이트마다 줄바꿈
                    if ((i + 1) % 16 == 0)
                        printf("\n");
                }
                printf("\n");
            }
            else { // message가 존재하지 않을 때
                printf("\n No application data \n");
            }

        }
    }
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}