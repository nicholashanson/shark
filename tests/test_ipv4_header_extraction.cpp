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
        0xad, 0xc2, 0x03, 0x49
    };

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( ethernet_frame );

    ASSERT_EQ( ipv4_header.size(), 20 );
} 