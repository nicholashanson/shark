#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( PacketParsingTests, TLSClientHello ) {
    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

TEST( PacketParsingTests, TLSClientHelloExtensions ) {
    
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );

    ASSERT_EQ( client_hello.extensions.size(), 185 );
}

TEST( PacketParsingTests, TLSServerHello ) {
    auto tls_record_span = std::span<const unsigned char>( test_constants::tls_server_hello_packet );;
    auto server_hello_span = tls_record_span.subspan( 9 );
    auto server_hello = ntk::parse_server_hello( server_hello_span );

    ASSERT_EQ( static_cast<ntk::cipher_suite>( server_hello.cipher_suite ), ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
    ASSERT_EQ( server_hello.session_id.size(), 32 );
}

TEST( PacketParsingTests, TLSRecordSplitting ) {

    const unsigned char first_packet[] = {
        // Record 1
        0x16, 0x03, 0x03, 0x00, 0x01, 0xAA,       // 6 bytes
        // Record 2
        0x17, 0x03, 0x03, 0x00, 0x01, 0xBB,       // 6 bytes
        // Partial Record 3 (incomplete, only 2 of 4 payload bytes)
        0x16, 0x03, 0x03, 0x00, 0x04, 0xCC, 0xDD  // 7 bytes (only first 2 payload bytes)
    };

    const unsigned char second_packet[] = {
        // Remaining 2 payload bytes for Record 3
        0xEE, 0xFF
    };

    auto [ first_records, first_offset ] = *ntk::split_tls_records( std::span( first_packet, sizeof( first_packet ) ) );

    ASSERT_EQ( first_records.size(), 2 );
    ASSERT_EQ( first_offset, 12 );

    std::vector<uint8_t> remainder( first_packet + first_offset, first_packet + sizeof( first_packet ) );
    remainder.insert( remainder.end(), second_packet, second_packet + sizeof( second_packet ) );

    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );

    ASSERT_EQ( second_records.size(), 1 );
    ASSERT_EQ( second_offset, 9 );
}

TEST( PacketParsingTests, TLSRecordSplittingPackets ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );

    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;

    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );

    ASSERT_EQ( first_records.size(), 2 );

    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );

    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );
    
    ASSERT_EQ( second_records.size(), 1 );
    ASSERT_EQ( second_offset, second_records[ 0 ].payload.size() + 5 );
    ASSERT_EQ( second_offset, remainder.size() );
}
