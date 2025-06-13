#include <gtest/gtest.h>

#include <tcp.hpp>
#include <spmc_queue.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( DataStructureTests, TinyCrossSPMCTransferQueuePushPop ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );

    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four );
    ntk::four_tuple_filter filter( four );

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::four_tuple_filter> tcp_live_stream_queue( filter );

    for ( auto& packet : packet_data ) {
        live_stream.feed( packet );
    }

    ASSERT_TRUE( live_stream.is_complete() );

    tcp_live_stream_queue.push( live_stream );

    auto popped_live_stream = tcp_live_stream_queue.try_pop();

    if ( !popped_live_stream ) {
        std::cerr << "Nothing popped from queue";
    }

    ASSERT_EQ( popped_live_stream.value(), live_stream );
}

TEST( DataStructureTests, TinyCrossSPMCTransferQueueFilterByFour ) {

    auto tiny_cross_packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto checkerboard_packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );

    auto tiny_cross_four_tuples = ntk::get_four_tuples( tiny_cross_packet_data );
    auto tiny_cross_four = *tiny_cross_four_tuples.begin();

    auto checkerboard_four_tuples = ntk::get_four_tuples( checkerboard_packet_data );
    auto checkerboard_four = *checkerboard_four_tuples.begin();

    ntk::tcp_live_stream tiny_cross_live_stream( tiny_cross_four );
    ntk::tcp_live_stream checkerboard_live_stream( checkerboard_four );
    ntk::four_tuple_filter filter( tiny_cross_four );

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::four_tuple_filter> tcp_live_stream_queue( filter );

    for ( auto& packet : tiny_cross_packet_data ) {
        tiny_cross_live_stream.feed( packet );
    }

    for ( auto& packet: checkerboard_packet_data ) {
        checkerboard_live_stream.feed( packet );
    }

    ASSERT_TRUE( tiny_cross_live_stream.is_complete() );
    ASSERT_TRUE( checkerboard_live_stream.is_complete() );

    tcp_live_stream_queue.push( checkerboard_live_stream );
    tcp_live_stream_queue.push( tiny_cross_live_stream );

    auto popped_live_stream = tcp_live_stream_queue.try_pop();

    if ( !popped_live_stream ) {
        std::cerr << "Nothing popped from queue";
    }

    ASSERT_EQ( popped_live_stream.value(), tiny_cross_live_stream );
}

TEST( DataStructureTests, EarthCamStaticTransferQueueFilterBySNI ) {

    auto earth_cam_static_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_static" ] );

    ntk::sni_filter filter( "earthcam" );

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::sni_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    for ( auto& packet : earth_cam_static_data ) {
        live_stream_session.feed( packet );
    }

    ASSERT_FALSE( offload_queue.empty() );
}



