#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <requests.hpp>
#include <utils.hpp>
#include <decompress.hpp>

#include <test_constants.hpp>

TEST( EarthCamVideoTests, ShortStream ) {

    std::vector<ntk::tls_record> verified_records;

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "short_stream" ] );

    auto four = *ntk::get_four_tuples( packet_data ).begin();

    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );

    auto client_tls_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_tls_records = ntk::extract_tls_records( server_payloads ).records;

    auto client_hello = ntk::get_client_hello( client_tls_records[ 0 ] );
    auto server_hello = ntk::get_server_hello( server_tls_records[ 0 ] );

    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    ntk::print_tls_secrets( secrets );

    ntk::print_client_hello( client_hello ); 
    ntk::print_server_hello( server_hello );

    std::cout << "tls record size: " << server_tls_records[ 3 ].payload.size() << std::endl; 

    auto decrypted_record_1 = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        server_tls_records[ 2 ],
        secrets,
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        0 );

    auto decrypted_record_2 = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        server_tls_records[ 3 ],
        secrets,
        "SERVER_TRAFFIC_SECRET_0",
        0 );

    std::cout << ntk::get_sni( client_hello ).value() << std::endl;

    ntk::print_vector( decrypted_record_2.payload );
}

TEST( EarthCamVideoTests, LongStream ) {

    std::vector<ntk::tls_record> verified_records;

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );

    auto four = *ntk::get_four_tuples( packet_data ).begin();

    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );

    auto client_tls_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_tls_records = ntk::extract_tls_records( server_payloads ).records;

    for ( auto& record : server_tls_records ) {
        ntk::print_tls_record( record );
    }

    auto client_hello = ntk::get_client_hello( client_tls_records[ 0 ] );
    auto server_hello = ntk::get_server_hello( server_tls_records[ 0 ] );

    std::vector<ntk::tls_record> client_records_to_decrypt( client_tls_records.begin() + 3, client_tls_records.end() );
    std::vector<ntk::tls_record> server_records_to_decrypt( server_tls_records.begin() + 3, server_tls_records.end() );

    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_client_tls_records = ntk::decrypt_tls_data(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        client_records_to_decrypt,
        secrets,
        "CLIENT_TRAFFIC_SECRET_0" );

    auto decrypted_server_tls_records = ntk::decrypt_tls_data(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        server_records_to_decrypt,
        secrets,
        "SERVER_TRAFFIC_SECRET_0" );

    for ( auto& record : decrypted_server_tls_records ) {
        record.payload.pop_back();
    }

    for ( auto& record : decrypted_client_tls_records ) {
        ntk::http_request request = ntk::get_http_request( record.payload );
        ntk::print_http_request( request );
    }

    ntk::http_response response = ntk::get_http_response(  decrypted_server_tls_records[ 2 ].payload  );

    for ( size_t i = 3; i < decrypted_server_tls_records.size(); ++i ) {
        response.body.insert( response.body.end(), decrypted_server_tls_records[ i ].payload.begin(), decrypted_server_tls_records[ i ].payload.end() );
    }

    ntk::print_http_response( response );

    ntk::write_payload_to_file( response.body, "segment.ts" );

}