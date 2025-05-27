#include <gtest/gtest.h>

#include <ipv4.hpp>

#include "test_constants.hpp"

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::ethernet_frame_udp );

    ASSERT_EQ( ipv4_header.size(), 20 );
}








