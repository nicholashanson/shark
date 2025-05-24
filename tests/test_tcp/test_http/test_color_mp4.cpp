#include <vector>

#include <gtest/gtest.h>

#include <http.hpp>
#include <utils.hpp>

TEST( PacketParsingTests, ExtractMP4 ) {

    auto packet_data = shark::read_packets_from_file( "../packet_data/color.txt" );

    auto http_response = shark::get_first_http_respone( packet_data );

    auto http_headers = shark::get_http_headers_from_payload( http_response );

    ASSERT_TRUE( shark::contains_http_header( http_headers, "Content-Length" ) );
}