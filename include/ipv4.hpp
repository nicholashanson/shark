#ifndef IPV4_HPP
#define IPV4_HPP

#include <algorithm>

#include <array>
#include <map>
#include <string>
#include <vector>
#include <tuple>
#include <unordered_map>
#include <sstream>

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
        HTTP = 0x50,    // HTTP: 80
        HTTPS = 0x01bb  // HTTPS: 443
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


    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    bool is_ipv4( const unsigned char* ethernet_frame );
    
} // namespace shark

#endif