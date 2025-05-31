#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>

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

TEST( PacketParsingTests, CertificateExtraction ) {

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

    std::vector<uint8_t> certificate_payload( decrypted_records[ 0 ].payload.begin() + 10, decrypted_records[ 0 ].payload.end() );

    auto certificate_bytes = ntk::extract_certificate( certificate_payload );

    ntk::print_vector( certificate_bytes );
}

TEST( PacketParsingTests, SrcDestIP ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

TEST( PacketParsingTests, TCPFilter ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );

    auto tcp_packets_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tcp_v );
    auto tcp_packets = std::vector<std::vector<uint8_t>>( tcp_packets_filter.begin(), tcp_packets_filter.end() );

    ASSERT_EQ( tcp_packets.size(), 19 );
}

TEST( PacketParsingTests, TLSFilter ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );

    auto tls_records_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tls_v );
    auto tls_records = std::vector<std::vector<uint8_t>>( tls_records_filter.begin(), tls_records_filter.end() );

    ASSERT_EQ( tls_records.size(), 5 );
}

TEST( PacketParsingTests, ClientHelloFilter ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );

    auto client_hello_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_client_hello_v );
    auto client_hellos = std::vector<std::vector<uint8_t>>( client_hello_filter.begin(), client_hello_filter.end() );

    ASSERT_EQ( client_hellos.size(), 1 );
}

TEST( PacketParsingTests, TCPLineNumbers ) {

    auto tcp_line_numbers = ntk::get_line_numbers( "../packet_data/tls_handshake.txt", ntk::is_tcp_v );

    ASSERT_EQ( tcp_line_numbers.size(), 19 );
}

TEST( PacketParsingTests, TLSRecordNumbers ) {

    auto tls_line_numbers = ntk::get_line_numbers( "../packet_data/tls_handshake.txt", ntk::is_tls_v );

    std::vector<int> expected_line_numbers = { 4, 6, 10, 12, 16 };

    ASSERT_EQ( tls_line_numbers.size(), 5 );
    ASSERT_EQ( tls_line_numbers, expected_line_numbers );
}

TEST( PacketParsingTests, ClientHelloLineNumbers ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( "../packet_data/tls_handshake.txt", ntk::is_client_hello_v );

    ASSERT_EQ( client_hello_line_numbers.size(), 1 );
    ASSERT_EQ( client_hello_line_numbers[ 0 ], 4 ); 
}

TEST( LiveStreamTests, ClientHelloLineNumbers ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( "../packet_data/earth_cam_live_stream.txt", ntk::is_client_hello_v );

    auto client_hello_packets = ntk::get_packets_by_line_numbers( "../packet_data/earth_cam_live_stream.txt", client_hello_line_numbers );

    ASSERT_EQ( client_hello_line_numbers.size(), client_hello_packets.size() );

    auto secrets = ntk::get_tls_secrets( "sslkeys.log" );

    std::vector<ntk::client_hello> client_hellos;

    for ( auto& client_hello_packet : client_hello_packets ) {
        auto tcp_payload = ntk::extract_payload_from_ethernet( client_hello_packet.data() );
        auto client_hello = ntk::get_client_hello( tcp_payload );
        client_hellos.push_back( client_hello );
    }
}

TEST( PacketParsingTests, ClientHelloSNI ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( "../packet_data/earth_cam_live_stream.txt", ntk::is_client_hello_v );

    auto client_hello_packets = ntk::get_packets_by_line_numbers( "../packet_data/earth_cam_live_stream.txt", client_hello_line_numbers );

    auto client_hello = ntk::get_client_hello_from_ethernet_frame( client_hello_packets[ 0 ] );
}