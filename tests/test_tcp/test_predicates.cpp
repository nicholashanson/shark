#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPDataPackets ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );

    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 0 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 1 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 2 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 3 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 4 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 5 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 6 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 7 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 8 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 9 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 10 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 11 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 12 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 13 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 14 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 15 ] ) );
}

TEST( PacketParsingTests, TCPSynPacket ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );

    ASSERT_TRUE( ntk::is_syn( packet_data[ 0 ] ) );
}

TEST( PacketParsingTests, TCPFilter ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );

    auto tcp_packets_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tcp_v );
    auto tcp_packets = std::vector<std::vector<uint8_t>>( tcp_packets_filter.begin(), tcp_packets_filter.end() );

    ASSERT_EQ( tcp_packets.size(), 19 );
}

TEST( PacketParsingTests, TCPLineNumbers ) {

    auto tcp_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_tcp_v );

    ASSERT_EQ( tcp_line_numbers.size(), 19 );
}

