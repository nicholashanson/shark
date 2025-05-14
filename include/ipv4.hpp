#ifndef IPV4_HPP
#define IPV4_HPP

#include <array>
#include <map>
#include <string>
#include <vector>

#include <cstdint>
#include <cstring>

#include <any>
#include <optional>
#include <stdexcept>

namespace shark {

    enum class protocol : uint8_t {
        TCP = 0x06,
        UDP = 0x11
    };

    enum class port_numbers : uint16_t {
        HTTP = 0x50,    // 80
        HTTPS = 0x01bb  // 443
    };

    struct ethernet_header {
        uint64_t src_mac_addr;
        uint64_t dest_mac_addr;
        uint16_t ethernet_type;
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

    struct tcp_header {
        uint16_t source_port;
        uint16_t destination_port;
        uint32_t sequence_number;
        uint32_t acknowledgment_number;
        uint16_t data_offset;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_pointer;

        std::optional<std::map<std::string,std::any>> options;

        bool operator==( const tcp_header& other ) const {
            return std::memcmp( this, &other, sizeof( tcp_header ) - sizeof( options ) ) == 0;
        }
    };

    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );
     
    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    udp_header parse_udp_header( const std::array<uint8_t,8>& raw_udp_header );

    bool is_ipv4( const unsigned char* ethernet_frame );

    bool is_udp( const unsigned char* ethernet_frame );

} // namespace shark

#endif