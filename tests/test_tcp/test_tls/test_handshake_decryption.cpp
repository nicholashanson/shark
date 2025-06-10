#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TLSParseSessionKeys ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_EQ( session_keys.size(), 2 );

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::extract_payload_from_ethernet( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    auto client_random_hex = ntk::client_random_to_hex( client_hello.random );

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

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
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

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
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

TEST( PacketParsingTests, CertificateExtraction ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
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

    std::vector<uint8_t> certificate_payload( decrypted_records[ 0 ].payload.begin() + 10, decrypted_records[ 0 ].payload.end() );

    auto certificate_bytes = ntk::extract_certificate( certificate_payload );

    ntk::print_vector( certificate_bytes );
}

