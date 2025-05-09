#ifndef IPV4_HPP
#define IPV4_HPP

#include <vector>
#include <cstdint>
#include <cstring>

namespace shark {

    enum class protocol {
        UDP = 0x11
    };

    struct ipv4_header {
        uint16_t total_length;
        uint8_t time_to_live;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_ip_addr;
        uint32_t destination_ip_addr;
    };

    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

} // namespace shark

#endif