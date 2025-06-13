#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPTrafficParsing ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    size_t data_packet_count = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_data_packet );

    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );

    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    const size_t number_of_resets = 2;

    EXPECT_EQ( client_traffic.size(), 3 );
    EXPECT_EQ( server_traffic.size(), data_packet_count - 3 - number_of_resets );
    EXPECT_EQ( data_packet_count, 8 );

    ASSERT_EQ( client_traffic[ 0 ], packet_data[ 3 ] );
    ASSERT_EQ( client_traffic[ 1 ], packet_data[ 9 ] );
    ASSERT_EQ( client_traffic[ 2 ], packet_data[ 15 ] );

    ASSERT_EQ( server_traffic[ 0 ], packet_data[ 5 ] );
    ASSERT_EQ( server_traffic[ 1 ], packet_data[ 7 ] );
    ASSERT_EQ( server_traffic[ 2 ], packet_data[ 11 ] );

    ASSERT_EQ( client_acks.size(), 4 );
    ASSERT_EQ( server_acks.size(), 4 );
}

TEST( TCPLiveStreamSession, OffloadQueueTLSFilter ) {

    ntk::tls_filter filter;

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );

    ASSERT_TRUE( offload_queue.empty() ) ;

    for ( auto& packet : packet_data ) {
        live_stream_session.feed( packet );
    }

    ASSERT_TRUE( live_stream_session.number_of_completed_transfers() == 0 );
    ASSERT_TRUE( offload_queue.empty() );
}