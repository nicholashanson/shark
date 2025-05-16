#include <gtest/gtest.h>

#include <ipv4.hpp>

#include <iomanip>

#include "qt.hpp"
#include "test_constants.hpp"

void print_tcp_options( const shark::tcp_header& header ) {
    for ( const auto& opt : header.options ) {
        std::cout << "Option kind: " << static_cast<int>( opt.type ) << " -> data bytes: ";
        for ( const auto& byte : opt.option ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;  // reset to decimal output
    }
}

TEST( PacketParsingTests, TCPSyn ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::tcp_syn_packet );
    
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = shark::extract_tcp_header( test::tcp_syn_packet, header.ihl );

    shark::tcp_header actual_header = shark::parse_tcp_header( tcp_bytes );

    shark::tcp_header expected_header = {
        .source_port = 44056,                    
        .destination_port = 3000,                
        .sequence_number = 0xb920c9b3,           
        .acknowledgment_number = 0,               
        .data_offset = 10,                        
        .window_size = 65535,                    
        .checksum = 5998,                         
        .urgent_pointer = 0,                   
        .options = {
            { 2, { 0x05, 0xb4 } },                                       // MSS = 1460
            { 4, {} },                                                   // SACK permitted (no data)
            { 8, { 0x02, 0x0d, 0x72, 0x64, 0x00, 0x00, 0x00, 0x00 } },   // Timestamp
            { 1, {} },                                                   // NOP
            { 3, { 0x09 } }                                              // Window Scale = 9
        }
    };

    ASSERT_EQ( expected_header, actual_header );
}

TEST( PacketParsingTests, TCPSynAck ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::tcp_synack_packet );
    
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = shark::extract_tcp_header( test::tcp_synack_packet, header.ihl );

    shark::tcp_header actual_header = shark::parse_tcp_header( tcp_bytes );

    shark::tcp_header expected_header = {
        .source_port = 3000,                     // 0x0bb8
        .destination_port = 44056,               // 0xac18
        .sequence_number = 0xd3c1ea09,           // bytes 34–37
        .acknowledgment_number = 0xb920c9b4,     // bytes 38–41
        .data_offset = 10,                       // 0xa0 >> 4 = 10 (i.e., 40 bytes total header)
        .window_size = 0xfe88,                   // bytes 44–45
        .checksum = 0x81a8,                      // bytes 46–47
        .urgent_pointer = 0x0000,                // bytes 48–49
        .options = {
            { 2, { 0x05, 0xb4 } },                                          // MSS
            { 4, {} },                                                      // SACK Permitted
            { 8, { 0x58, 0x64, 0xbc, 0x69, 0x02, 0x0d, 0x72, 0x64 } },      // Timestamp
            { 1, {} },                                                      // NOP
            { 3, { 0x07 } }                                                 // Window Scale = 7
        }
    };

    ASSERT_EQ( expected_header, actual_header );
}

TEST( PacketParsingTests, TCPAck ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::tcp_ack_packet );
    
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = shark::extract_tcp_header( test::tcp_ack_packet, header.ihl );

    shark::tcp_header actual_header = shark::parse_tcp_header( tcp_bytes );

    shark::tcp_header expected_header = {
        .source_port = 44056,                      // 0xac18
        .destination_port = 3000,                  // 0x0bb8
        .sequence_number = 0xb920c9b4,             // bytes 34-37
        .acknowledgment_number = 0xd3c1ea0a,       // bytes 38-41
        .data_offset = 8,                          // 0x80 >> 4 = 8 (32 bytes TCP header)
        .window_size = 0x0080,                     // bytes 44-45
        .checksum = 0x72de,                        // bytes 46-47
        .urgent_pointer = 0x0000,                  // bytes 48-49
        .options = {
            { 1, {} },                             // NOP
            { 1, {} },                             // NOP
            { 8, { 0x02, 0x0d, 0x72, 0x97, 0x58, 0x64, 0xbc, 0x69 } }   // Timestamp
        }
    };

    ASSERT_EQ( expected_header, actual_header );
}

TEST( PacketParsingTests, HttpPayloadLen ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload( test::http_get_packet );

    ASSERT_EQ( http_payload.size(), 354 );
}

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_udp );

    ASSERT_EQ( ipv4_header.size(), 20 );
}

TEST( PacketParsingTests, HttpPayloadSectionLengths ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload( test::http_get_packet );

    auto http_sections = shark::split_http_payload( http_payload );

    ASSERT_EQ( std::get<0>( http_sections ).size(), 14 );
    ASSERT_EQ( std::get<1>( http_sections ).size(), 334 );
    ASSERT_EQ( std::get<2>( http_sections ).size(), 0 );
}

TEST( PacketParsingTests, HttpRequestLine ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload( test::http_get_packet );

    auto http_sections = shark::split_http_payload( http_payload );

    shark::http_request_line r_line = shark::parse_http_request_line( std::get<0>( http_sections ) );

    ASSERT_EQ( r_line.method_token, "GET" );
}

TEST( PacketParsingTests, HttpHeader ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload( test::http_get_packet );

    auto http_sections = shark::split_http_payload( http_payload );

    shark::http_headers headers = shark::parse_http_headers( std::get<1>( http_sections ) );

    ASSERT_EQ( headers[ "Host" ], "192.168.0.21:3000" );
}

TEST( PacketParsingTests, UDPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_udp );

    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::UDP ) );

    std::array<uint8_t,8> udp_header = shark::extract_udp_header( test::ethernet_frame_udp, header.ihl );

    ASSERT_EQ( udp_header[ 0 ], 0x01 );

    shark::udp_header parsed_udp_header = shark::parse_udp_header( udp_header );

    ASSERT_EQ( parsed_udp_header.source_port, static_cast<uint16_t>( shark::port_numbers::HTTPS ) );
}

TEST( PacketParsingTests, TCPHeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_tcp );
    
    shark::ipv4_header header = shark::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( shark::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = shark::extract_tcp_header( test::ethernet_frame_tcp, header.ihl );

    shark::tcp_header expected_header = {
        .source_port = 443,
        .destination_port = 52684,
        .sequence_number = 0x9fa50857,
        .acknowledgment_number = 0x1d4203b7,
        .data_offset = 5,
        .window_size = 0x4002,
        .checksum = 0x952f,
        .urgent_pointer = 0
    };

    shark::tcp_header actual_header = shark::parse_tcp_header( tcp_bytes );

    ASSERT_EQ( expected_header, actual_header );
}

TEST( PacketParsingTests, HttpType ) {

    auto http_request_payload = shark::extract_http_payload( test::http_get_packet );
    auto http_response_payload = shark::extract_http_payload( test::http_response_packet );

    shark::http_type request_type = shark::get_http_type( http_request_payload );
    shark::http_type response_type = shark::get_http_type( http_response_payload );

    ASSERT_EQ( request_type, shark::http_type::REQUEST );
    ASSERT_EQ( response_type, shark::http_type::RESPONSE );
}

TEST( PacketParsingTests, HttpResponseStatusLine ) {

    auto http_payload = shark::extract_http_payload( test::http_response_packet );

    auto http_sections = shark::split_http_payload( http_payload );

    auto htpp_response_status_line = shark::parse_http_response_status_line( std::get<0>( http_sections ) );

    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}

TEST( PacketParsingTests, VisualCheckParsedText ) {

    auto http_payload = shark::extract_http_payload( test::http_response_packet );

    auto http_sections = shark::split_http_payload( http_payload );

    auto http_content = std::get<2>( http_sections ); 

    EXPECT_FALSE( http_content.empty() );

    auto dechunked_http_content = shark::decode_single_chunk( http_content ); 

    std::string http_content_string( dechunked_http_content.begin(), dechunked_http_content.end() );

    test::show_text_in_qt_window( QString::fromStdString( http_content_string ) );
}





