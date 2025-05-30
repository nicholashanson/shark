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

    ASSERT_EQ( client_hello.session_id.size(), 32 );
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

TEST( PacketParsingTests, TLSParseSessionKeys ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_EQ( session_keys.size(), 2 );

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::extract_payload_from_ethernet( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    auto client_random_hex = ntk::client_random_to_hex( client_hello.random );

    ASSERT_EQ( session_keys.size(), 2 );
    ASSERT_TRUE( session_keys.contains( client_random_hex ) );
}

TEST( PacketParsingTests, TLSNonce ) {

    std::vector<uint8_t> base_iv = { 0x00 ,0x01 ,0x02 ,0x03, 
                                     0x04, 0x05, 0x06, 0x07, 
                                     0x08, 0x09, 0x0a, 0x0b };

    uint64_t seq_num = 0x0102030405060708;

    auto actual_nonce = ntk::build_tls13_nonce( base_iv, seq_num );

    std::vector<uint8_t> expected_nonce = {
        0x00, 0x01, 0x02, 0x03,
        0x05, 0x07, 0x05, 0x03,
        0x0D, 0x0F, 0x0D, 0x03
    };

    ASSERT_EQ( actual_nonce, expected_nonce );
}

TEST( PacketParsingTests, TLSDecryption ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );

    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;

    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );

    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );

    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );

    // extract and parse client-hello
    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::extract_payload_from_ethernet( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    // parse server-hello
    tls_record_span = std::span<const unsigned char>( first_records[ 0 ].payload );
    auto server_hello = ntk::parse_server_hello( tls_record_span );

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto decrypted_records = ntk::decrypt_tls_data( client_hello.random, server_hello.random, server_hello.server_version, 
        server_hello.cipher_suite, second_records, session_keys );

    ASSERT_EQ( decrypted_records.size(), 1 );
}

TEST( PacketParsingTests, HKDFExpand ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::extract_payload_from_ethernet( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto secret = ntk::get_traffic_secret( session_keys, client_hello.random, "CLIENT_TRAFFIC_SECRET_0" );    

    std::string key = "04c5bdf5bccbf7740b09250614979949aa7a6d5b57f4dc15aa8f46fee288c9a4";
    std::string iv = "1cd7b5120945932eb3ca91e5";

    auto km = ntk::derive_tls_key_iv( secret, EVP_sha384(), 32, 12 );

    std::ostringstream oss;
    for ( auto b : km.key )
        oss << std::hex << std::setw( 2 ) << std::setfill( '0' )  << static_cast<int>( b );

    ASSERT_EQ( key, oss.str() );

    oss.str( "" );
    oss.clear();

    for ( auto b : km.iv )
        oss << std::hex << std::setw( 2 ) << std::setfill( '0' )  << static_cast<int>( b );

    ASSERT_EQ( iv, oss.str() );
}

