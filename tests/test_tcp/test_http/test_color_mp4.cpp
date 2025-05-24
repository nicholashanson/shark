#include <vector>

#include <gtest/gtest.h>

#include <http.hpp>
#include <utils.hpp>

#include <cstdlib>

TEST( PacketParsingTests, MP4ContentLengthHeader ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/color.txt" );
    auto http_response = shark::get_first_http_respone( packet_data );
    auto http_headers = shark::get_http_headers_from_payload( http_response );

    ASSERT_TRUE( shark::contains_http_header( http_headers, "Content-Length" ) );
}

TEST( PacketParsingTests, ExtractMP4 ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/color.txt" );
    auto merged_stream = shark::get_merged_tcp_stream( packet_data );

    std::cout << "got merged stream" << std::endl;

    auto response_data = shark::get_http_response_data( merged_stream ); 

    std::cout << "got response data" << std::endl;

    auto http_response = shark::get_first_http_respone( packet_data );
    auto http_headers = shark::get_http_headers_from_payload( http_response );

    ASSERT_EQ( std::stoul( http_headers[ "Content-Length" ] ), response_data.size() );
}