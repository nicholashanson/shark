#include <gtest/gtest.h>

#include <ipv4.hpp>
#include <tcp.hpp>
#include <http.hpp>
#include <udp.hpp>
#include <utils.hpp>

#include <iomanip>

#include "qt.hpp"
#include "test_constants.hpp"

void print_vector( const std::vector<uint8_t>& data ) {
    for ( auto byte : data ) {
        std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
    }
    std::cout << std::dec << std::endl;
}

void print_tcp_stream_info(const std::map<uint32_t, std::vector<uint8_t>>& stream) {
    for (const auto& [seq_num, data] : stream) {
        std::cout << "Seq: " << seq_num 
                  << ", Size: " << data.size() << " bytes\n";
    }
}

void print_tcp_options( const shark::tcp_header& header ) {
    for ( const auto& opt : header.options ) {
        std::cout << "Option kind: " << static_cast<int>( opt.type ) << " -> data bytes: ";
        for ( const auto& byte : opt.option ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;  
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
        .data_offset = 10,                                               // 40 bytes                    
        .window_size = 65535,                                            
        .checksum = 5998,                                                
        .urgent_pointer = 0,                                             
        .options = {                                                        
            { 2, { 0x05, 0xb4 } },                                       // MSS
            { 4, {} },                                                   // SACK permitted
            { 8, { 0x02, 0x0d, 0x72, 0x64, 0x00, 0x00, 0x00, 0x00 } },   // timestamp
            { 1, {} },                                                   // nop
            { 3, { 0x09 } }                                              // window scale
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
        .source_port = 3000,                                                // 0x0bb8
        .destination_port = 44056,                                          // 0xac18
        .sequence_number = 0xd3c1ea09,           
        .acknowledgment_number = 0xb920c9b4,     
        .data_offset = 10,                                                  // 40 bytes 
        .window_size = 0xfe88,                   
        .checksum = 0x81a8,                      
        .urgent_pointer = 0x0000,                
        .options = {
            { 2, { 0x05, 0xb4 } },                                          // MSS
            { 4, {} },                                                      // SACK permitted
            { 8, { 0x58, 0x64, 0xbc, 0x69, 0x02, 0x0d, 0x72, 0x64 } },      // timestamp
            { 1, {} },                                                      // nop
            { 3, { 0x07 } }                                                 // window scale 
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
        .source_port = 44056,                                           // 0xac18
        .destination_port = 3000,                                       // 0x0bb8
        .sequence_number = 0xb920c9b4,             
        .acknowledgment_number = 0xd3c1ea0a,       
        .data_offset = 8,                                               // 32 bytes 
        .window_size = 0x0080,                     
        .checksum = 0x72de,                        
        .urgent_pointer = 0x0000,                  
        .options = {
            { 1, {} },                                                  // nop
            { 1, {} },                                                  // nop
            { 8, { 0x02, 0x0d, 0x72, 0x97, 0x58, 0x64, 0xbc, 0x69 } }   // timestamp
        }
    };

    ASSERT_EQ( expected_header, actual_header );
}

TEST( PacketParsingTests, HttpPayloadLen ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload_from_ethernet( test::http_get_packet );

    ASSERT_EQ( http_payload.size(), 354 );
}

TEST( PacketParsingTests, IPV4HeaderExtraction ) {

    std::vector<uint8_t> ipv4_header = shark::extract_ipv4_header( test::ethernet_frame_udp );

    ASSERT_EQ( ipv4_header.size(), 20 );
}

TEST( PacketParsingTests, HttpPayloadSectionLengths ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = shark::split_http_payload( http_payload );

    ASSERT_EQ( std::get<0>( http_sections ).size(), 14 );
    ASSERT_EQ( std::get<1>( http_sections ).size(), 334 );
    ASSERT_EQ( std::get<2>( http_sections ).size(), 0 );
}

TEST( PacketParsingTests, HttpRequestLine ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = shark::split_http_payload( http_payload );
    shark::http_request_line r_line = shark::parse_http_request_line( std::get<0>( http_sections ) );

    ASSERT_EQ( r_line.method_token, "GET" );
}

TEST( PacketParsingTests, HttpHeader ) {

    std::vector<uint8_t> http_payload = shark::extract_http_payload_from_ethernet( test::http_get_packet );
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

    auto http_request_payload = shark::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_response_payload = shark::extract_http_payload_from_ethernet( test::http_response_packet );

    shark::http_type request_type = shark::get_http_type( http_request_payload );
    shark::http_type response_type = shark::get_http_type( http_response_payload );

    ASSERT_EQ( request_type, shark::http_type::REQUEST );
    ASSERT_EQ( response_type, shark::http_type::RESPONSE );
}

TEST( PacketParsingTests, HttpResponseStatusLine ) {

    auto http_payload = shark::extract_http_payload_from_ethernet( test::http_response_packet );
    auto http_sections = shark::split_http_payload( http_payload );
    auto htpp_response_status_line = shark::parse_http_status_line( std::get<0>( http_sections ) );

    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}

TEST( PacketParsingTests, VisualCheckParsedText ) {

    auto http_payload = shark::extract_http_payload_from_ethernet( test::http_response_packet );
    auto http_sections = shark::split_http_payload( http_payload );
    auto http_content = std::get<2>( http_sections ); 

    EXPECT_FALSE( http_content.empty() );

    auto dechunked_http_content = shark::decode_single_chunk( http_content ); 
    std::string http_content_string( dechunked_http_content.begin(), dechunked_http_content.end() );

    test::show_text_in_qt_window( QString::fromStdString( http_content_string ) );
}

TEST( UtilitiesTest, ReadPacketDataFromFile ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/tiny_cross.txt" );

    ASSERT_EQ( packet_data.size(), 13 );
}

TEST( PacketParsingTests, RawTCPStreamLength ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto raw_stream = shark::extract_raw_tcp_stream( packet_data );

    ASSERT_EQ( raw_stream.size(), 2 );
}

TEST( PacketParsingTests, BitMapImageExtaction ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/tiny_cross.txt" );
    auto raw_stream = shark::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = shark::get_tcp_stream( raw_stream );
    
    auto response = *std::find_if( tcp_stream.begin(), tcp_stream.end(), 
        []( const auto& pair ) { 
            auto& [unused, http_payload] = pair;
            return shark::get_http_type( http_payload) == shark::http_type::RESPONSE;
        } 
    );

    auto [ http_status_line, http_headers, http_body ] = shark::split_http_payload( response.second );

    auto dechunked_body = shark::decode_single_chunk( http_body );

    test::show_bitmap_in_qt_window( dechunked_body );
}

TEST( PacketParsingTests, TCPStreamMerging ) {

    shark::tcp_stream overlapping_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },    
        { 1004, { 'E', 'F', 'G' } },          
        { 1002, { 'C', 'D', 'E', 'F' } },     
        { 1010, { 'H', 'I' } },              
        { 1003, { 'D', 'E', 'F' } }            
    };

    shark::tcp_stream actual_merged_stream = shark::merge_tcp_stream_non_overlapping( overlapping_stream );

    shark::tcp_stream expected_merged_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },
        { 1004, { 'E', 'F' } },
        { 1006, { 'G' } },
        { 1010, { 'H', 'I' } }
    };

    ASSERT_EQ( actual_merged_stream, expected_merged_stream );
}

TEST( PacketParsingTests, LenStreamNonOverlapping ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = shark::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = shark::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = shark::merge_tcp_stream_non_overlapping( tcp_stream );

    ASSERT_TRUE( shark::is_non_overlapping_stream( merged_tcp_stream ) );
}

TEST( PacketParsingTests, LenStreamZeroChunk ) {

    auto ends_with_zero_chunk = []( const shark::tcp_stream& stream ) -> bool {

        const auto& [ seq, data ] = *stream.rbegin();

        std::vector<uint8_t> zero_chunk_pattern = { '\r', '\n', '\r', '\n' };

        return std::equal(
            zero_chunk_pattern.rbegin(),
            zero_chunk_pattern.rend(),
            data.rbegin()
        );
    };

    auto packet_data = shark::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = shark::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = shark::get_tcp_stream( raw_stream );
    
    EXPECT_TRUE( ends_with_zero_chunk( tcp_stream ) ) << "Last TCP segment does not end with the zero chunk.";

    auto merged_tcp_stream = shark::merge_tcp_stream_non_overlapping( tcp_stream );

    EXPECT_TRUE( ends_with_zero_chunk( merged_tcp_stream ) ) << "Last TCP segment does not end with the zero chunk.";
}

TEST( PacketParsingTests, LenaVisualTest ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = shark::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = shark::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = shark::merge_tcp_stream_non_overlapping( tcp_stream );

    std::vector<uint8_t> lena_image;

    for ( auto& [ sequence_number, tcp_body ] : merged_tcp_stream ) {

        if ( shark::get_http_type( tcp_body ) == shark::http_type::REQUEST ) {
            continue;
        }

        if ( shark::get_http_type( tcp_body ) == shark::http_type::RESPONSE ) {
            auto [ status_line, headers, body ] = shark::split_http_payload( tcp_body );
            tcp_body = body;
        } 

        lena_image.insert( lena_image.end(), tcp_body.begin(), tcp_body.end() );
    } 

    auto decoded_lena_image = shark::decode_chunked_http_body( lena_image );

    std::ofstream out( "lena.bmp", std::ios::binary );
    out.write( reinterpret_cast<const char*>( decoded_lena_image.data() ), decoded_lena_image.size() );

    test::show_bitmap_in_qt_window( decoded_lena_image );
}

TEST( PacketParsingTests, HTTPChunkedBodyDecoding ) {

    std::vector<uint8_t> chunked_data = {
        '4', '\r', '\n', 'W', 'i', 'k', 'i', '\r', '\n',
        '5', '\r', '\n', 'p', 'e', 'd', 'i', 'a', '\r', '\n',
        '0', '\r', '\n', '\r', '\n'
    };

    auto actual_decoded_data = shark::decode_chunked_http_body( chunked_data ); 

    std::vector<uint8_t> expected_decoded_data = {
        'W', 'i', 'k', 'i',
        'p', 'e', 'd', 'i', 'a'
    };

    ASSERT_EQ( expected_decoded_data, actual_decoded_data );
}



