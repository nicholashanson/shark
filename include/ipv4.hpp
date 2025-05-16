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

    struct http_response_status_line {
        std::string http_version;
        int status_code;
        std::string reason_phrase;
    };

    enum class http_type {
        REQUEST,
        RESPONSE
    };

    using http_headers = std::unordered_map<std::string,std::string>;

    enum class protocol : uint8_t {
        TCP = 0x06,
        UDP = 0x11
    };

    enum class port_numbers : uint16_t {
        HTTP = 0x50,    // HTTP: 80
        HTTPS = 0x01bb  // HTTPS: 443
    };

    struct http_request_line {
        std::string method_token;
        std::string path;
        std::string http_version;
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

    struct tcp_option {
        uint8_t type;
        std::vector<uint8_t> option;

        bool operator==( const tcp_option& other ) const {
            return type == other.type && option == other.option;
        }        
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

        std::vector<tcp_option> options;

        bool operator==( const tcp_header& other ) const {
            return source_port == other.source_port &&
                destination_port == other.destination_port &&
                sequence_number == other.sequence_number &&
                acknowledgment_number == other.acknowledgment_number &&
                data_offset == other.data_offset &&
                window_size == other.window_size &&
                checksum == other.checksum &&
                urgent_pointer == other.urgent_pointer &&
                options == other.options;
        }
    };

    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );
     
    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    std::vector<uint8_t> extract_http_payload( const unsigned char* ethernet_frame );

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    split_http_payload( const std::vector<uint8_t>& payload );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    udp_header parse_udp_header( const std::array<uint8_t,8>& raw_udp_header );

    tcp_header parse_tcp_header( const std::vector<uint8_t>& raw_tcp_header );

    bool is_ipv4( const unsigned char* ethernet_frame );

    bool is_udp( const unsigned char* ethernet_frame );

    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes );

    // TODO: check http rules on whitespace in headers
    std::string trim( const std::string& str );

    http_headers parse_http_headers( const std::vector<uint8_t>& header_bytes );

    http_type get_http_type( const std::vector<uint8_t>& http_payload );

    http_response_status_line parse_http_response_status_line( const std::vector<uint8_t>& status_line_bytes );
} // namespace shark

#endif