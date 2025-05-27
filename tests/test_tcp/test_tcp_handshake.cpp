#include <ipv4.hpp>
#include <tcp.hpp>

#include <vector>

#include <iomanip>

#include <gtest/gtest.h>

#include <test_constants.hpp>

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

void print_tcp_options( const ntk::tcp_header& header ) {
    for ( const auto& opt : header.options ) {
        std::cout << "Option kind: " << static_cast<int>( opt.type ) << " -> data bytes: ";
        for ( const auto& byte : opt.option ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;  
    }
}

TEST( PacketParsingTests, TCPSyn ) {

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::tcp_syn_packet );
    ntk::ipv4_header header = ntk::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( ntk::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = ntk::extract_tcp_header( test::tcp_syn_packet, header.ihl );
    ntk::tcp_header actual_header = ntk::parse_tcp_header( tcp_bytes );

    ntk::tcp_header expected_header = {
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

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::tcp_synack_packet );
    ntk::ipv4_header header = ntk::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( ntk::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = ntk::extract_tcp_header( test::tcp_synack_packet, header.ihl );
    ntk::tcp_header actual_header = ntk::parse_tcp_header( tcp_bytes );

    ntk::tcp_header expected_header = {
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

    std::vector<uint8_t> ipv4_header = ntk::extract_ipv4_header( test::tcp_ack_packet );
    ntk::ipv4_header header = ntk::parse_ipv4_header( ipv4_header );

    ASSERT_EQ( header.protocol, static_cast<unsigned char>( ntk::protocol::TCP ) );

    std::vector<uint8_t> tcp_bytes = ntk::extract_tcp_header( test::tcp_ack_packet, header.ihl );
    ntk::tcp_header actual_header = ntk::parse_tcp_header( tcp_bytes );

    ntk::tcp_header expected_header = {
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