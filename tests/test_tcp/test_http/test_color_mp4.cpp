#include <vector>

#include <gtest/gtest.h>

#include <http.hpp>
#include <utils.hpp>

#include <qt.hpp>

#include <cstdlib>

TEST( PacketParsingTests, MP4ContentLengthHeader ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/color.txt" );
    auto http_response = ntk::get_first_http_respone( packet_data );
    auto http_headers = ntk::get_http_headers_from_payload( http_response );

    ASSERT_TRUE( ntk::contains_http_header( http_headers, "Content-Length" ) );
}

TEST( PacketParsingTests, ExtractMP4 ) {

    auto packet_data = ntk::read_packets_from_file( "../packet_data/color.txt" );
    
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto response_data = ntk::get_http_response_data( merged_stream ); 

    auto http_response = ntk::get_first_http_respone( packet_data );
    auto http_headers = ntk::get_http_headers_from_payload( http_response );

    ASSERT_EQ( std::stoul( http_headers[ "Content-Length" ] ), response_data.size() );

    test::show_mp4_in_qt_window( response_data ); 
}