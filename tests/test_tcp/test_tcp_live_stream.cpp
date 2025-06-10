#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <utils.hpp>
#include <test_constants.hpp>

TEST( PacketParsingTests, TCPCheckerBoardLiveStream ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        
        live_stream.feed( packet );

        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ 2 ] );

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );

    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence[ 0 ], packet_data[ 25 ] );
    ASSERT_EQ( closing_sequence[ 1 ], packet_data[ 28 ] );
    ASSERT_EQ( closing_sequence[ 2 ], packet_data[ 26 ] );
    ASSERT_EQ( closing_sequence[ 3 ], packet_data[ 27 ] );

    auto& traffic = ntk::tcp_live_stream_friend_helper::traffic( live_stream );

    ASSERT_EQ( traffic.size(), 22 );
}

TEST( PacketParsingTests, TCPTinyCrossLiveStream ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        
        live_stream.feed( packet );

        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ 2 ] );

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );

    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence[ 0 ], packet_data[ 9 ] );
    ASSERT_EQ( closing_sequence[ 1 ], packet_data[ 12 ] );
    ASSERT_EQ( closing_sequence[ 2 ], packet_data[ 10 ] );
    ASSERT_EQ( closing_sequence[ 3 ], packet_data[ 11 ] );
}