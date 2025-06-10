#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, ClientHelloFilter ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );

    auto client_hello_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_client_hello_v );
    auto client_hellos = std::vector<std::vector<uint8_t>>( client_hello_filter.begin(), client_hello_filter.end() );

    ASSERT_EQ( client_hellos.size(), 1 );
}

TEST( PacketParsingTests, TLSFilter ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );

    auto tls_records_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tls_v );
    auto tls_records = std::vector<std::vector<uint8_t>>( tls_records_filter.begin(), tls_records_filter.end() );

    ASSERT_EQ( tls_records.size(), 5 );
}

TEST( PacketParsingTests, TLSRecordNumbers ) {
 
    auto tls_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_tls_v );

    std::vector<int> expected_line_numbers = { 4, 6, 10, 12, 16 };

    ASSERT_EQ( tls_line_numbers.size(), 5 );
    ASSERT_EQ( tls_line_numbers, expected_line_numbers );
}

TEST( PacketParsingTests, ClientHelloLineNumbers ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_client_hello_v );

    ASSERT_EQ( client_hello_line_numbers.size(), 1 );
    ASSERT_EQ( client_hello_line_numbers[ 0 ], 4 ); 
}

TEST( LiveStreamTests, ClientHelloLineNumbers ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::is_client_hello_v );

    ASSERT_TRUE( !client_hello_line_numbers.empty() );

    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );

    ASSERT_TRUE( !client_hello_packets.empty() );
    ASSERT_EQ( client_hello_line_numbers.size(), client_hello_packets.size() );

    auto secrets = ntk::get_tls_secrets( "sslkeys.log" );

    std::vector<ntk::client_hello> client_hellos;

    for ( auto& client_hello_packet : client_hello_packets ) {
        auto tcp_payload = ntk::extract_payload_from_ethernet( client_hello_packet.data() );
        auto client_hello = ntk::get_client_hello( tcp_payload );
        client_hellos.push_back( client_hello );
    }
}