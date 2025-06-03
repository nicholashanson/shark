#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_tcp_handshake_packets.hpp>

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

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_helllo_record = ntk::extract_payload_from_ethernet( tls_client_hello.data() );

    ASSERT_EQ( client_helllo_record.size(), 329 );
}

TEST( PacketParsingTests, TLSClientHelloFromEthernetFrame ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

TEST( PacketParsingTests, TLSAlertParsing ) {

    auto [ records, offset_reached ] = *ntk::split_tls_records( test_constants::tls_alert_packet ); 

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    ASSERT_EQ( records.size(), 2 );
    ASSERT_EQ( offset_reached, sizeof( test_constants::tls_alert_packet ) );

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

    ntk::print_vector( decrypted_records[ 0 ].payload );
}

TEST( PacketParsingTests, TLSApplicationDataParsing ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

    ntk::print_vector( second_decrypted_record.payload );
}

TEST( PacketParsingTests, TLSHandshakeParsing ) {

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    ASSERT_TRUE( !session_keys.empty() );

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
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

TEST( LiveStreamTests, TLSGetSNIs ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_live_stream.txt" );

    auto snis = ntk::get_snis( packet_data, "earthcam" );

    ASSERT_TRUE( !snis.empty() );
}

TEST( LiveStreamTests, TLSSni2Ip ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_live_stream.txt" );

    auto sni_2_ip = ntk::get_sni_to_ip( packet_data );

    ASSERT_TRUE( !sni_2_ip.empty() );
    
    for ( auto [ sni, ip ] : sni_2_ip ) {
        std::cout << sni << ": " << static_cast<int>( ip ) << std::endl;
    }

    ASSERT_TRUE( sni_2_ip.contains( "videos-3.earthcam.com" ) );

    std::cout << ntk::ip_to_string( sni_2_ip[ "videos-3.earthcam.com" ] ) << std::endl;
}

TEST( PacketParsingTests, FourTuple ) {

    ntk::four_tuple four = ntk::get_four_from_ethernet( test_constants::tcp_syn_packet );

    ntk::four_tuple expected_four = { 
        .client_ip = 0xc0a80014,
        .server_ip = 0xc0a80015,
        .client_port = 0xac18,
        .server_port = 0x0bb8
    };

    ASSERT_EQ( four, expected_four );
}

TEST( PacketParsingTests, FourTupleSet ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );

    ASSERT_EQ( four_tuples.size(), 1 ); 
}

TEST( PacketParsingTests, TCPHandshakeDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = ntk::get_handshake( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( tcp_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( tcp_handshake.ack, packet_data[ 2 ] );
}

TEST( PacketParsingTests, TCPHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( LiveStreamTests, TCPHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_video.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshakes = ntk::get_handshakes( four_tuple, packet_data );

    ASSERT_EQ( tcp_handshakes.size(), 1 );
}

TEST( PacketParsingTests, TCPTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_EQ( std::get<ntk::rst>( tcp_termination.closing_sequence ), packet_data[ 17 ] );
}

TEST( PacketParsingTests, TCPHandshakeSequenceNumbers ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_handshake = ntk::get_handshake( four_tuple, packet_data );

    auto syn_header = ntk::get_tcp_header( tcp_handshake.syn.data() );
    auto syn_ack_header = ntk::get_tcp_header( tcp_handshake.syn_ack.data() );
    auto ack_header = ntk::get_tcp_header( tcp_handshake.ack.data() );

    ASSERT_EQ( syn_ack_header.acknowledgment_number, syn_header.sequence_number + 1 );
    ASSERT_EQ( ack_header.acknowledgment_number, syn_ack_header.sequence_number + 1 );
    ASSERT_EQ( ack_header.sequence_number, syn_header.sequence_number + 1 );
}
