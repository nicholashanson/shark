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

    auto [ second_records, second_offset ] = *ntk::split_tls_records(remainder);

    ASSERT_EQ( second_records.size(), 1 );
    ASSERT_EQ( second_offset, 9 );
}


/*
TEST( PacketParsingTests, TLSRecordSplitting ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto tls_response = ntk::extract_payload_from_ethernet( packet_data[ 5 ].data() );

    auto tls_response_span = std::span<const unsigned char>( tls_response );

    std::cout << "about to split records" << std::endl;
    auto tls_records = ntk::split_tls_records( tls_response_span );

    std::cout << tls_records->size();
}
*/