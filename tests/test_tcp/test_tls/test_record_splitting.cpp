#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, TLSRecordSplitting ) {

    const unsigned char first_packet[] = {
        // record 1
        0x16, 0x03, 0x03, 0x00, 0x01, 0xaa,       // 6 bytes
        // record 2
        0x17, 0x03, 0x03, 0x00, 0x01, 0xbb,       // 6 bytes
        // partial record 3 ( incomplete, only 2 of 4 payload bytes )
        0x16, 0x03, 0x03, 0x00, 0x04, 0xcc, 0xdd  // 7 bytes ( only first 2 payload bytes )
    };

    const unsigned char second_packet[] = {
        // remaining 2 payload bytes for record 3
        0xee, 0xff
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

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
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