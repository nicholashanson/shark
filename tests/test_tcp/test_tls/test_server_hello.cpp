#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TLSServerHello ) {
    auto tls_record_span = std::span<const unsigned char>( test_constants::tls_server_hello_packet );;
    auto server_hello_span = tls_record_span.subspan( 9 );
    auto server_hello = ntk::parse_server_hello( server_hello_span );

    ASSERT_EQ( static_cast<ntk::cipher_suite>( server_hello.cipher_suite ), ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
    ASSERT_EQ( server_hello.session_id.size(), 32 );
}

TEST( PacketParsingTests, TLSServerHelloEquivalance ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );

    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    
    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );

    // parse server-hello
    auto tls_record_span = std::span<const unsigned char>( first_records[ 0 ].payload ).subspan( 4 );
    auto server_hello = ntk::parse_server_hello( tls_record_span );
    ASSERT_EQ( static_cast<ntk::cipher_suite>( server_hello.cipher_suite ), ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
}
