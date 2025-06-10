#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <requests.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPHandshakeDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = ntk::get_handshake( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( tcp_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( tcp_handshake.ack, packet_data[ 2 ] );
}

TEST( PacketParsingTests, TCPHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( PacketParsingTests, TCPCheckerBoardHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( LiveStreamTests, TCPHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( LiveStreamTests, TCPEarthCamHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( PacketParsingTests, TCPHandshakeSequenceNumbers ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ]);
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = ntk::get_handshake( four_tuple, packet_data );

    auto syn_header = ntk::get_tcp_header( tcp_handshake.syn.data() );
    auto syn_ack_header = ntk::get_tcp_header( tcp_handshake.syn_ack.data() );
    auto ack_header = ntk::get_tcp_header( tcp_handshake.ack.data() );

    ASSERT_EQ( syn_ack_header.acknowledgment_number, syn_header.sequence_number + 1 );
    ASSERT_EQ( ack_header.acknowledgment_number, syn_ack_header.sequence_number + 1 );
    ASSERT_EQ( ack_header.sequence_number, syn_header.sequence_number + 1 );
}

TEST( PacketParsingTests, TCPEndOfHandshake ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto handshake = ntk::get_handshake( four_tuple, packet_data );

    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, four_tuple, handshake );

    auto& end_of_handshake = packet_data[ 2 ];

    ASSERT_NE( end_of_handshake_ptr, nullptr );
    ASSERT_EQ( *end_of_handshake_ptr, end_of_handshake );
}