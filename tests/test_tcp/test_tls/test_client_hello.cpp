#include <gtest/gtest.h>

#include <pcap.h>

#include <span>
#include <cstdint>

#include <packet_listener.hpp>
#include <tls.hpp>
#include <requests.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_tcp_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( PacketParsingTests, TLSClientHello ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];

    ASSERT_EQ( sizeof( test_constants::tls_client_hello_packet ), tls_client_hello.size() );

    auto tls_client_hello_bytes = ntk::extract_payload_from_ethernet( test_constants::tls_client_hello_packet );

    ASSERT_EQ( tls_client_hello_bytes.size(), 329 );

    auto tls_record_span = std::span<const uint8_t>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    ASSERT_EQ( client_hello.client_version, 0x0303 );
    ASSERT_EQ( client_hello.session_id.size(), 32 );
    ASSERT_EQ( ntk::session_id_to_hex( client_hello.session_id ), "73a6f6977049af5160801e6221d25c8e4a502f7edcddae5712b90cbcde75d09a" );
    ASSERT_EQ( ntk::client_random_to_hex( client_hello.random ), "7ba900c7057e9e5d0609c04b66f56e1b3003cd6906dea3cec057f8f733cc7102" );
    ASSERT_EQ( client_hello.cipher_suites.size(), 62 );
    ASSERT_EQ( client_hello.compression_methods.size(), 1 );
    ASSERT_EQ( client_hello.extensions.size(), 185 );
}

TEST( PacketParsingTests, TLSClientHelloEthernetFrame ) {
    
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );

    ASSERT_EQ( client_hello.client_version, 0x0303 );
    ASSERT_EQ( client_hello.session_id.size(), 32 );
    ASSERT_EQ( ntk::session_id_to_hex( client_hello.session_id ), "73a6f6977049af5160801e6221d25c8e4a502f7edcddae5712b90cbcde75d09a" );
    ASSERT_EQ( ntk::client_random_to_hex( client_hello.random ), "7ba900c7057e9e5d0609c04b66f56e1b3003cd6906dea3cec057f8f733cc7102" );
    ASSERT_EQ( client_hello.cipher_suites.size(), 62 );
    ASSERT_EQ( client_hello.compression_methods.size(), 1 );
    ASSERT_EQ( client_hello.extensions.size(), 185 );
}

TEST( PacketParsingTests, TLSClientHelloTCPPayload ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_helllo_record = ntk::extract_payload_from_ethernet( tls_client_hello.data() );

    ASSERT_EQ( client_helllo_record.size(), 329 );
}

TEST( PacketParsingTests, TLSClientHelloFromEthernetFrame ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( tls_client_hello );

    ASSERT_EQ( client_hello.client_version, 0x0303 );
    ASSERT_EQ( client_hello.session_id.size(), 32 );
    ASSERT_EQ( ntk::session_id_to_hex( client_hello.session_id ), "363c4edf91f14d388547a75f371187ec468d84de548eecfa5dbb4a97390da0a4" );
    ASSERT_EQ( ntk::client_random_to_hex( client_hello.random ), "e7bb2bb068dcd517e4f4ba1475e9d936dded3c24627c1b80861f2ca24a645a37" );
    ASSERT_EQ( client_hello.cipher_suites.size(), 62 );
    ASSERT_EQ( client_hello.compression_methods.size(), 1 );
    ASSERT_EQ( client_hello.extensions.size(), 185 );
}

TEST( PacketParsingTests, TLSClientHelloExtensions ) {
    
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );

    ASSERT_EQ( client_hello.extensions.size(), 185 );
}