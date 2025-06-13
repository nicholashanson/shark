#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <pcap.h>

#include <constants.hpp>

#include <iomanip>
#include <iostream>
#include <fstream>

namespace ntk {

    inline const char* filters[] = {
        "tcp port 3000",
        "tcp port 443",
        "tcp port 443 and (host 104.22.21.231 or host 104.22.20.231 or host 172.67.10.24)"
    };

    void packet_handler( unsigned char* user_data, 
                         const struct pcap_pkthdr* pkthdr, 
                         const unsigned char* packet ); 

    void write_packet_to_file( unsigned char* user_data,
                               const struct pcap_pkthdr* pkthdr,
                               const unsigned char* packet );

    pcap_if_t* list_and_select_device();

    pcap_t* open_device( pcap_if_t* device );

    pcap_t* open_device( const char* device_name );

    bool apply_filter( pcap_t* handle, const char* filter_exp );

    int run_capture_loop( pcap_t* handle, std::ofstream &file_handle );

    int run_capture_loop( pcap_t* handle, pcap_handler callback, u_char* user_data );

    void capture_packets( const std::string& filename );

} // namespace ntk

#endif

