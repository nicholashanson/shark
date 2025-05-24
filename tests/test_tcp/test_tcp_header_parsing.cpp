#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_tcp );
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = shark::extract_tcp_header( test::ethernet_frame_tcp, header.ihl );

    shark::tcp_header expected_header = {
        .source_port = 443,
        .destination_port = 52684,
        .sequence_number = 0x9fa50857,
        .acknowledgment_number = 0x1d4203b7,
        .data_offset = 5,
        .window_size = 0x4002,
        .checksum = 0x952f,
        .urgent_pointer = 0
    };

    shark::tcp_header actual_header = shark::parse_tcp_header( tcp_bytes );

    ASSERT_EQ( expected_header, actual_header );
}
