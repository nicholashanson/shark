#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TCPLenaFinAcks ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto is_fin_ack = [&]( const auto& packet ) {
        auto packet_tcp_header = ntk::get_tcp_header( packet.data() );
        return ( packet_tcp_header.flags & static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK );
    };

    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), is_fin_ack );

    ASSERT_EQ( num_fin_acks, 2 );
}

TEST( LiveStreamTests, TCPEathCamVideoFinAcks ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_video" ] );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto is_fin_ack = [&]( const auto& packet ) {
        auto packet_tcp_header = ntk::get_tcp_header( packet.data() );
        return ( packet_tcp_header.flags & static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK );
    };

    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), is_fin_ack );

    ASSERT_EQ( num_fin_acks, 2 );
}