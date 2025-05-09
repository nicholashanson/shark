#ifndef IPV4_HPP
#define IPV4_HPP

#include <array>
#include <vector>
#include <cstdint>
#include <cstring>

namespace shark {

    enum class protocol : uint8_t {
        TCP = 0x06,
        UDP = 0x11
    };

    enum class port_numbers : uint16_t {
        HTTPS = 0x01bb // 443
    };

    struct ipv4_header {
        size_t ihl; // internet header length in bytes
        uint16_t total_length;
        uint8_t time_to_live;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_ip_addr;
        uint32_t destination_ip_addr;
    };

    struct udp_header {
        uint16_t source_port;
        uint16_t destination_port;
        uint16_t length;
        uint16_t checksum;
    };

    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    udp_header parse_udp_header( const std::array<uint8_t,8>& raw_udp_header );

} // namespace shark

#endif