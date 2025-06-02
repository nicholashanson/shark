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
#include <ranges>

#include <cstdint>
#include <cstring>

#include <any>
#include <optional>
#include <stdexcept>

#include <constants.hpp>

namespace ntk {

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

    using sender_reciever = std::pair<uint32_t,uint32_t>;

    /*
        takes a raw ethernet frame and extracts the ipv4 header
    */
    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame );

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header );

    ipv4_header get_ipv4_header( const unsigned char* ethernet_frame );

    struct ipv4_filter {
        uint32_t ip_addr;

        bool operator()( const std::vector<uint8_t>& packet ) const {
            auto header = get_ipv4_header( packet.data() );
            
            return ( header.source_ip_addr == ip_addr ) || ( header.destination_ip_addr == ip_addr );
        }
    };

    sender_reciever get_sender_reciever( const unsigned char* ethernet_frame );

    sender_reciever flip_sender_reciever( const sender_reciever& src_dest );

    inline decltype(auto) filter_by_ip( const session& packets, const sender_reciever& src_dest ) {
    
        return std::views::all( packets ) | std::views::filter( [ & ] ( const auto& packet ) {
            return get_sender_reciever( packet.data() ) == src_dest;
        });
    }

    inline decltype(auto) filter_by_ip_duplex( const session& packets, const sender_reciever& src_dest ) {

        auto dest_src = flip_sender_reciever( src_dest );
    
        return std::views::all( packets ) | std::views::filter( [ & ] ( const auto& packet ) {
            auto ip_pair = get_sender_reciever( packet.data() );
            return ip_pair == src_dest || ip_pair == dest_src;
        });
    }

    bool is_ipv4( const unsigned char* ethernet_frame );

    std::string ip_to_string( uint32_t ip );
    
} // namespace ntk

#endif