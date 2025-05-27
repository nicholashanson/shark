#include <gtest/gtest.h>

#include <vector>

#include <ipv4.hpp>
#include <udp.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, UDPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::ethernet_frame_udp );
    ntk::ipv4_header header = ntk::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( ntk::protocol::UDP ) );

    std::array<uint8_t,8> udp_header = ntk::extract_udp_header( test::ethernet_frame_udp, header.ihl );

    ASSERT_EQ( udp_header[ 0 ], 0x01 );

    ntk::udp_header parsed_udp_header = ntk::parse_udp_header( udp_header );

    ASSERT_EQ( parsed_udp_header.source_port, static_cast<uint16_t>( ntk::port_numbers::HTTPS ) );
}