#include <algorithm>

#include <gtest/gtest.h>

#include <tcp.hpp>
#include <http.hpp>
#include <utils.hpp>

#include <qt.hpp>

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
            auto& [ unused, http_payload ] = pair;
            return shark::get_http_type( http_payload ) == shark::http_type::RESPONSE;
        } 
    );

    auto [ http_status_line, http_headers, http_body ] = shark::split_http_payload( response.second );

    auto dechunked_body = shark::decode_single_chunk( http_body );

    test::show_bitmap_in_qt_window( dechunked_body );
}