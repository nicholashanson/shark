#include <gtest/gtest.h>

#include <ipv4.hpp>
#include <utils.hpp>

#include "test_constants.hpp"

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::ethernet_frame_udp );

    ASSERT_EQ( ipv4_header.size(), 20 );
}


TEST( PacketParsingTests, SrcDestIP ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& first_packet = packet_data[ 0 ];
    auto client_server = ntk::get_sender_reciever( first_packet.data() );

    auto client_packets_filter = ntk::filter_by_ip( packet_data, client_server );
    auto client_packets = std::vector<std::vector<uint8_t>>( client_packets_filter.begin(), client_packets_filter.end() );

    ASSERT_EQ( client_packets.size(), 9 );

    auto server_client = ntk::flip_sender_reciever( client_server );

    auto server_packets_filter = ntk::filter_by_ip( packet_data, server_client );
    auto server_packets = std::vector<std::vector<uint8_t>>( server_packets_filter.begin(), server_packets_filter.end() );

    ASSERT_EQ( server_packets.size(), 10 );
}








