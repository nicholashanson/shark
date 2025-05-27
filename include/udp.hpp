#ifndef UDP_HPP
#define UDP_HPP

#include <constants.hpp>

#include <array>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ntk {

    struct udp_header {
        uint16_t source_port;
        uint16_t destination_port;
        uint16_t length;
        uint16_t checksum;
    };

    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    udp_header parse_udp_header( const std::array<uint8_t,8>& raw_udp_header );

    bool is_udp( const unsigned char* ethernet_frame );

} // end namesapce

#endif