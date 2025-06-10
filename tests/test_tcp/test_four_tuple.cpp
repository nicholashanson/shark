#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <utils.hpp>

#include <test_tcp_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( PacketParsingTests, FourTuple ) {

    ntk::four_tuple four = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );

    ntk::four_tuple expected_four = { 
        .client_ip = 0xc0a80014,
        .server_ip = 0xc0a80015,
        .client_port = 0xac18,
        .server_port = 0x0bb8
    };

    ASSERT_EQ( four, expected_four );
}

TEST( PacketParsingTests, TLSHandShakeFourTupleSet ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );

    ASSERT_EQ( four_tuples.size(), 1 ); 
}

TEST( PacketParsingTests, CheckerBoardFourTupleSet ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );

    ASSERT_EQ( four_tuples.size(), 1 ); 
}

TEST( PacketParsingTests, TinyCrossFourTupleSet ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );

    ASSERT_EQ( four_tuples.size(), 1 ); 
}