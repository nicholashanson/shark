#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( PacketParsingTests, TLSAlertParsing ) {

    auto [ records, offset_reached ] = *ntk::split_tls_records( test_constants::tls_alert_packet ); 

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    ASSERT_EQ( records.size(), 2 );
    ASSERT_EQ( offset_reached, sizeof( test_constants::tls_alert_packet ) );

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( tls_client_hello );

    auto& tls_server_hello = packet_data[ 5 ];
    auto server_hello = ntk::get_server_hello_from_ethernet_frame( tls_server_hello );

    std::cout << ntk::client_random_to_hex( client_hello.random ) << std::endl;

    std::vector<ntk::tls_record> encrypted_records( records.begin() + 1, records.end() );

    ASSERT_EQ( encrypted_records[ 0 ].payload.size(), 69 );

    auto decrypted_records = ntk::decrypt_tls_data(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records,
        session_keys,
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET" );

    ASSERT_EQ( decrypted_records.size(), 1 );
    ASSERT_EQ( decrypted_records[ 0 ].payload.size(), encrypted_records[ 0 ].payload.size() - 16 );
}

TEST( PacketParsingTests, TLSApplicationDataParsing ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( tls_client_hello );

    auto& tls_server_hello = packet_data[ 5 ];
    auto server_hello = ntk::get_server_hello_from_ethernet_frame( tls_server_hello );

    auto& tls_record = packet_data[ 11 ];
    auto tls_application_data = ntk::extract_payload_from_ethernet( tls_record.data() );
    
    auto [ encrypted_records, offset_reached ] = *ntk::split_tls_records( 
        std::span( tls_application_data.data(), tls_application_data.size() ) );

    ASSERT_EQ( encrypted_records.size(), 2 );

    auto first_decrypted_record = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records[ 0 ],
        session_keys,
        "SERVER_TRAFFIC_SECRET_0",
        0 );

    auto second_decrypted_record = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records[ 1 ],
        session_keys,
        "SERVER_TRAFFIC_SECRET_0",
        1 );
}

TEST( PacketParsingTests, TLSHandshakeParsing ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( tls_client_hello );

    auto& tls_server_hello = packet_data[ 5 ];
    auto server_hello = ntk::get_server_hello_from_ethernet_frame( tls_server_hello );

    auto& tls_record = packet_data[ 15 ];
    auto tls_application_data = ntk::extract_payload_from_ethernet( tls_record.data() );
    
    auto [ encrypted_records, offset_reached ] = *ntk::split_tls_records( 
        std::span( tls_application_data.data(), tls_application_data.size() ) );

    ASSERT_EQ( encrypted_records.size(), 1 );

    auto decrypted_record = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records[ 0 ],
        session_keys,
        "CLIENT_TRAFFIC_SECRET_0",
        0 );
 
    ntk::print_vector( decrypted_record.payload );
}