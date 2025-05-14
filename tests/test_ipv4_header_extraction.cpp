#include <gtest/gtest.h>

#include <ipv4.hpp>

#include "test_constants.hpp"

TEST( PacketParsingTests, TCPHandshake ) {
}

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_udp );

    ASSERT_EQ( ipv4_header.size(), 20 );
}

TEST( PacketParsingTests, UDPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_udp );

    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::UDP ) );

    std::array<uint8_t,8> udp_header = shark::extract_udp_header( test::ethernet_frame_udp, header.ihl );

    ASSERT_EQ( udp_header[ 0 ], 0x01 );

    shark::udp_header parsed_udp_header = shark::parse_udp_header( udp_header );

    ASSERT_EQ( parsed_udp_header.source_port, static_cast<uint16_t>( shark::port_numbers::HTTPS ) );
}

TEST( PacketParsingTests, TCPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_tcp );
    
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_header = shark::extract_tcp_header( test::ethernet_frame_tcp, header.ihl );

    ASSERT_EQ( tcp_header.size(), 20 );
} 



