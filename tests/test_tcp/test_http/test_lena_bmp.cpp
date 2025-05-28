#include <gtest/gtest.h>

#include <vector>

#include <fstream>

#include <tcp.hpp>
#include <http.hpp>
#include <utils.hpp>

#include <test_constants.hpp>
#include <qt.hpp>

TEST( PacketParsingTests, LenStreamNonOverlapping ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = ntk::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );

    ASSERT_TRUE( ntk::is_non_overlapping_stream( merged_tcp_stream ) );
}

TEST( PacketParsingTests, LenStreamZeroChunk ) {

    auto ends_with_zero_chunk = []( const ntk::tcp_stream& stream ) -> bool {

        const auto& [ seq, data ] = *stream.rbegin();

        std::vector<uint8_t> zero_chunk_pattern = { '\r', '\n', '\r', '\n' };

        return std::equal(
            zero_chunk_pattern.rbegin(),
            zero_chunk_pattern.rend(),
            data.rbegin()
        );
    };

    auto packet_data = ntk::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = ntk::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    
    EXPECT_TRUE( ends_with_zero_chunk( tcp_stream ) ) << "Last TCP segment does not end with the zero chunk.";

    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );

    EXPECT_TRUE( ends_with_zero_chunk( merged_tcp_stream ) ) << "Last TCP segment does not end with the zero chunk.";
}

TEST( PacketParsingTests, LenaVisualTest ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/lena.txt" );
    auto raw_stream = ntk::extract_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );

    std::vector<uint8_t> lena_image;

    for ( auto& [ sequence_number, tcp_body ] : merged_tcp_stream ) {

        if ( ntk::get_http_type( tcp_body ) == ntk::http_type::REQUEST ) {
            continue;
        }

        if ( ntk::get_http_type( tcp_body ) == ntk::http_type::RESPONSE ) {
            auto [ status_line, headers, body ] = ntk::split_http_payload( tcp_body );
            tcp_body = body;
        } 

        lena_image.insert( lena_image.end(), tcp_body.begin(), tcp_body.end() );
    } 

    auto decoded_lena_image = ntk::decode_chunked_http_body( lena_image );

    std::ofstream out( "lena.bmp", std::ios::binary );
    out.write( reinterpret_cast<const char*>( decoded_lena_image.data() ), decoded_lena_image.size() );

    test::show_bitmap_in_qt_window( decoded_lena_image );
}