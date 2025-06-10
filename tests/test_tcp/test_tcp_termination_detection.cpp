#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_EQ( std::get<ntk::rst>( tcp_termination.closing_sequence ), packet_data[ 17 ] );
}

TEST( PacketParsingTests, TCPTinyCrossTerminationsDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( PacketParsingTests, TCPCheckerBoardDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( PacketParsingTests, TCPTinyCrossTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_TRUE( std::holds_alternative<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence ) );

    auto& seq = std::get<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence );

    ASSERT_EQ( seq[ 0 ], packet_data[ 9 ] );
    ASSERT_EQ( seq[ 1 ], packet_data[ 12 ] );
    ASSERT_EQ( seq[ 2 ], packet_data[ 10 ] );
    ASSERT_EQ( seq[ 3 ], packet_data[ 11 ] ); 
}

TEST( PacketParsingTests, TCPLenaTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_TRUE( std::holds_alternative<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence ) );

    auto& seq = std::get<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence );

    ASSERT_EQ( seq[ 0 ], packet_data[ 458 ] );
    ASSERT_EQ( seq[ 1 ], packet_data[ 459 ] );
    ASSERT_EQ( seq[ 2 ], packet_data[ 459 ] );
    ASSERT_EQ( seq[ 3 ], packet_data[ 460 ] ); 
}

TEST( LiveStreamTests, TCPEarthCamVideoTerminationsDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    auto number_of_resets = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_reset );

    ASSERT_EQ( tcp_terminations.size(), number_of_resets );
}

TEST( PacketParsingTests, TCPTinyCrossTerminationStartDetection ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, four_tuple, tcp_termination );

    ASSERT_NE( start_of_termination_ptr, nullptr );
}

TEST( PacketParsingTests, TCPStartOfTermination ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ]  );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto termination = ntk::get_termination( four_tuple, packet_data );

    auto termination_header = ntk::get_tcp_header( std::get<ntk::rst>( termination.closing_sequence ).data() );

    auto& termination_start = packet_data[ 17 ];

    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, four_tuple, termination );

    ASSERT_NE( start_of_termination_ptr, nullptr );
    ASSERT_EQ( *start_of_termination_ptr, termination_start );
    ASSERT_EQ( static_cast<int>( termination_header.sequence_number ), 1441872756 );
}
