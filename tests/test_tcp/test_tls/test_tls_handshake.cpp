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

TEST( PacketParsingTests, TCPCheckerBoardHandshakesDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/checkerboard.txt" );
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

TEST( LiveStreamTests, TCPEarthCamHandshakesDetection ) {

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

TEST( PacketParsingTests, TCPEndOfHandshake ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto handshake = ntk::get_handshake( four_tuple, packet_data );

    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, four_tuple, handshake );

    auto& end_of_handshake = packet_data[ 2 ];

    ASSERT_NE( end_of_handshake_ptr, nullptr );
    ASSERT_EQ( *end_of_handshake_ptr, end_of_handshake );
}

TEST( PacketParsingTests, TCPLenaFinAcks ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto is_fin_ack = [&]( const auto& packet ) {
        auto packet_tcp_header = ntk::get_tcp_header( packet.data() );
        return ( packet_tcp_header.flags & static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK );
    };

    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), is_fin_ack );

    ASSERT_EQ( num_fin_acks, 2 );
}

TEST( LiveStreamTests, TCPEathCamVideoFinAcks ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_video.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto is_fin_ack = [&]( const auto& packet ) {
        auto packet_tcp_header = ntk::get_tcp_header( packet.data() );
        return ( packet_tcp_header.flags & static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( ntk::tcp_flags::FIN_ACK );
    };

    auto num_fin_acks = std::count_if( packet_data.begin(), packet_data.end(), is_fin_ack );

    ASSERT_EQ( num_fin_acks, 2 );
}

TEST( PacketParsingTests, TCPTinyCrossTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_TRUE( std::holds_alternative<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence ) );

    auto& seq = std::get<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence );

    ASSERT_EQ( seq[ 0 ], packet_data[ 9 ] );
    ASSERT_EQ( seq[ 1 ], packet_data[ 12 ] );
    ASSERT_EQ( seq[ 2 ], packet_data[ 10 ] );
    ASSERT_EQ( seq[ 3 ], packet_data[ 11 ] ); 
}

TEST( PacketParsingTests, TCPLenaTerminationDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/lena.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    ASSERT_TRUE( std::holds_alternative<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence ) );

    auto& seq = std::get<ntk::fin_ack_fin_ack>( tcp_termination.closing_sequence );

    ASSERT_EQ( seq[ 0 ], packet_data[ 458 ] );
    ASSERT_EQ( seq[ 1 ], packet_data[ 459 ] );
    ASSERT_EQ( seq[ 2 ], packet_data[ 459 ] );
    ASSERT_EQ( seq[ 3 ], packet_data[ 460 ] ); 
}

TEST( PacketParsingTests, TCPTinyCrossTerminationsDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( PacketParsingTests, TCPCheckerBoardDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/checkerboard.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    ASSERT_EQ( tcp_terminations.size(), 1 );
}

TEST( LiveStreamTests, TCPEarthCamVideoTerminationsDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_video.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_terminations = ntk::get_terminations( four_tuple, packet_data );

    auto number_of_resets = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_reset );

    ASSERT_EQ( tcp_terminations.size(), number_of_resets );
}

TEST( PacketParsingTests, TCPTinyCrossTerminationStartDetection ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto tcp_termination = ntk::get_termination( four_tuple, packet_data );

    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, four_tuple, tcp_termination );

    ASSERT_NE( start_of_termination_ptr, nullptr );
}

TEST( PacketParsingTests, TCPStartOfTermination ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();
    auto termination = ntk::get_termination( four_tuple, packet_data );

    auto termination_header = ntk::get_tcp_header( std::get<ntk::rst>( termination.closing_sequence ).data() );

    auto& termination_start = packet_data[ 17 ];

    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, four_tuple, termination );

    ASSERT_NE( start_of_termination_ptr, nullptr );
    ASSERT_EQ( *start_of_termination_ptr, termination_start );
    ASSERT_EQ( static_cast<int>( termination_header.sequence_number ), 1441872756 );
}

TEST( PacketParsingTests, TCPSpanSize ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    auto termination = ntk::get_termination( four_tuple, packet_data );
    auto start_of_termination_ptr = ntk::get_start_of_termination( packet_data, four_tuple, termination );

    auto handshake = ntk::get_handshake( four_tuple, packet_data );
    auto end_of_handshake_ptr = ntk::get_end_of_handshake( packet_data, four_tuple, handshake );

    auto size = static_cast<size_t>( start_of_termination_ptr - end_of_handshake_ptr );

    ASSERT_EQ( size, 15 );
}

TEST( PacketParsingTests, TCPTrafficParsing ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    size_t data_packet_count = std::count_if( packet_data.begin(), packet_data.end(), ntk::is_data_packet );

    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );

    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    const size_t number_of_resets = 2;

    EXPECT_EQ( client_traffic.size(), 3 );
    EXPECT_EQ( server_traffic.size(), data_packet_count - 3 - number_of_resets );
    EXPECT_EQ( data_packet_count, 8 );

    ASSERT_EQ( client_traffic[ 0 ], packet_data[ 3 ] );
    ASSERT_EQ( client_traffic[ 1 ], packet_data[ 9 ] );
    ASSERT_EQ( client_traffic[ 2 ], packet_data[ 15 ] );

    ASSERT_EQ( server_traffic[ 0 ], packet_data[ 5 ] );
    ASSERT_EQ( server_traffic[ 1 ], packet_data[ 7 ] );
    ASSERT_EQ( server_traffic[ 2 ], packet_data[ 11 ] );

    ASSERT_EQ( client_acks.size(), 4 );
    ASSERT_EQ( server_acks.size(), 4 );
}

TEST( PacketParsingTests, TCPDataPackets ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tls_handshake.txt" );

    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 0 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 1 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 2 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 3 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 4 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 5 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 6 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 7 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 8 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 9 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 10 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 11 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 12 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 13 ] ) );
    ASSERT_FALSE( ntk::is_data_packet( packet_data[ 14 ] ) );
    ASSERT_TRUE( ntk::is_data_packet( packet_data[ 15 ] ) );
}

TEST( LiveStreamTests, TCPEarthCamVideoSeqAckMatching ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/earth_cam_video.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );

    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    for ( auto& server_packet : server_traffic ) {
    
        size_t payload_length = ntk::extract_payload_from_ethernet( server_packet.data() ).size();

        ntk::tcp_header server_tcp_header = ntk::get_tcp_header( server_packet.data() );

        uint32_t expected_ack = server_tcp_header.sequence_number + static_cast<uint32_t>( payload_length );

        std::cout << "expected ack: " << expected_ack << std::endl;

        bool found = std::any_of( client_acks.begin(), client_acks.end(),
            [&]( const std::vector<uint8_t>& client_packet ) {
                ntk::tcp_header client_tcp_header = ntk::get_tcp_header( client_packet.data() );
                return client_tcp_header.acknowledgment_number == expected_ack;
        });

        ASSERT_TRUE( found );
    }
}


TEST( PacketParsingTests, TCPTinyCrossSeqAckMatching ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tls_over_tcp tls_transfer( four_tuple );
    tls_transfer.load( packet_data );

    std::cout << "loaded packet data" << std::endl;

    auto& client_traffic = ntk::tcp_transfer_friend_helper::client_traffic( tls_transfer );
    auto& server_traffic = ntk::tcp_transfer_friend_helper::server_traffic( tls_transfer );
    auto& client_acks = ntk::tcp_transfer_friend_helper::client_acks( tls_transfer );
    auto& server_acks = ntk::tcp_transfer_friend_helper::server_acks( tls_transfer );

    for ( auto& server_packet : server_traffic ) {
    
        size_t payload_length = ntk::extract_payload_from_ethernet( server_packet.data() ).size();

        ntk::tcp_header server_tcp_header = ntk::get_tcp_header( server_packet.data() );

        uint32_t expected_ack = server_tcp_header.sequence_number + static_cast<uint32_t>( payload_length );

        std::cout << "expected ack: " << expected_ack << std::endl;

        bool found = std::any_of( client_acks.begin(), client_acks.end(),
            [&]( const std::vector<uint8_t>& client_packet ) {
                ntk::tcp_header client_tcp_header = ntk::get_tcp_header( client_packet.data() );
                std::cout << "server ack: " << client_tcp_header.acknowledgment_number << std::endl;
                return client_tcp_header.acknowledgment_number == expected_ack;
        });

        ASSERT_TRUE( found );
    }
}

TEST( PacketParsingTests, TCPSynPacket ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/checkerboard.txt" );

    ASSERT_TRUE( ntk::is_syn( packet_data[ 0 ] ) );
}

TEST( PacketParsingTests, TCPCheckerBoardLiveStream ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/checkerboard.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        
        live_stream.feed( packet );

        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ 2 ] );

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );

    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence[ 0 ], packet_data[ 25 ] );
    ASSERT_EQ( closing_sequence[ 1 ], packet_data[ 28 ] );
    ASSERT_EQ( closing_sequence[ 2 ], packet_data[ 26 ] );
    ASSERT_EQ( closing_sequence[ 3 ], packet_data[ 27 ] );

    auto& traffic = ntk::tcp_live_stream_friend_helper::traffic( live_stream );

    ASSERT_EQ( traffic.size(), 22 );
}

TEST( PacketParsingTests, TCPTinyCrossStream ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto four_tuples = ntk::get_four_tuples( packet_data );
    auto four_tuple = *four_tuples.begin();

    ntk::tcp_live_stream live_stream( four_tuple );

    for ( auto& packet : packet_data ) {
        
        live_stream.feed( packet );

        if ( live_stream.is_complete() ) break;
    }

    ASSERT_TRUE( live_stream.is_complete() );

    auto& handshake_feed = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream );

    ASSERT_EQ( handshake_feed.m_handshake.syn, packet_data[ 0 ] );
    ASSERT_EQ( handshake_feed.m_handshake.syn_ack, packet_data[ 1 ] );
    ASSERT_EQ( handshake_feed.m_handshake.ack, packet_data[ 2 ] );

    auto& termination_feed = ntk::tcp_live_stream_friend_helper::termination_feed( live_stream );

    auto& closing_sequence = std::get<ntk::fin_ack_fin_ack>( termination_feed.m_termination.closing_sequence );

    ASSERT_EQ( closing_sequence[ 0 ], packet_data[ 9 ] );
    ASSERT_EQ( closing_sequence[ 1 ], packet_data[ 12 ] );
    ASSERT_EQ( closing_sequence[ 2 ], packet_data[ 10 ] );
    ASSERT_EQ( closing_sequence[ 3 ], packet_data[ 11 ] );
}

TEST( PacketParsingTests, TCPLiveStreamSession ) {

    std::vector<std::string> files = {
        "../packet_data/checkerboard.txt",
        "../packet_data/tiny_cross.txt",
    };

    std::vector<ntk::session> transfer_data;

    for ( auto& file : files ) {
        auto packet_data = ntk::read_packets_from_file( file );
        transfer_data.push_back( packet_data );   
    }

    size_t max_size = -std::numeric_limits<size_t>::max();
    for ( auto& transfer : transfer_data ) {
        if ( transfer.size() > max_size ) max_size = transfer.size();
    }

    ntk::session combined_packets;

    for ( size_t i = 0; i < max_size; ++i ) {

        for ( auto& transfer : transfer_data ) {
            if ( i < transfer.size() ) combined_packets.push_back( transfer[ i ] );
        }
    }

    ntk::tcp_live_stream_session live_stream_session;

    for ( auto& packet : combined_packets ) {
        live_stream_session.feed( packet );
    }

    ASSERT_EQ( live_stream_session.number_of_completed_transfers(), transfer_data.size() );
}




