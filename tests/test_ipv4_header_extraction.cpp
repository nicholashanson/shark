#include <gtest/gtest.h>

#include <ipv4.hpp>

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    const unsigned char ethernet_frame[] = {
        /* ethernet header */
        // destination mac address
        0x04, 0x81, 0x9b, 0x17, 0x26, 0x81,
        // source mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa, 
        // ether-type
        0x08, 0x00, // 0x08 indicates ipv4
        
        /* ipv4 header */
        // version and header length
        0x45, // version = 4, header length = 5 X 4 = 20 bytes
        // DSCP and ECN
        0x00,
        // total length of packet
        0x00, 0x3f, 
        // identification
        0xdd, 0x2e, 
        // flags and fragment offset
        0x40, 0x00, 
        // time-to-live
        0x40, 
        // protocol
        0x11,
        // header checksum
        0x00, 0x00, 
        // source IP address
        0xc0, 0xa8, 0x00, 0x15, 
        // destination IP address
        0xad, 0xc2, 0x03, 0x49,

        /* udp header */
        // source port
        0x01, 0xbb,
        // destination port
        0xce, 0xb9, 
        // length
        0x04, 0xea, 
        // checksum
        0x01, 0xb8
    };

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( ethernet_frame );

    ASSERT_EQ( ipv4_header.size(), 20 );

    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::UDP ) );
    
    std::array<uint8_t,8> udp_header = shark::extract_udp_header( ethernet_frame, header.ihl );

    ASSERT_EQ( udp_header[ 0 ], 0x01 );

    shark::udp_header parsed_udp_header = shark::parse_udp_header( udp_header );

    ASSERT_EQ( parsed_udp_header.source_port, static_cast<uint16_t>( shark::port_numbers::HTTPS ) );

} 