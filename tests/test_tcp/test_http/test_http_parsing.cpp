#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, HttpPayloadLen ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );

    ASSERT_EQ( http_payload.size(), 354 );
}

TEST( PacketParsingTests, HttpPayloadSectionLengths ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );

    ASSERT_EQ( std::get<0>( http_sections ).size(), 14 );
    ASSERT_EQ( std::get<1>( http_sections ).size(), 334 );
    ASSERT_EQ( std::get<2>( http_sections ).size(), 0 );
}

TEST( PacketParsingTests, HttpRequestLine ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_request_line r_line = ntk::parse_http_request_line( std::get<0>( http_sections ) );

    ASSERT_EQ( r_line.method_token, "GET" );
}

TEST( PacketParsingTests, HttpHeader ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    ntk::http_headers headers = ntk::parse_http_headers( std::get<1>( http_sections ) );

    ASSERT_EQ( headers[ "Host" ], "192.168.0.21:3000" );
}

TEST( PacketParsingTests, HttpType ) {

    auto http_request_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_response_payload = ntk::extract_http_payload_from_ethernet( test::http_response_packet );

    ntk::http_type request_type = ntk::get_http_type( http_request_payload );
    ntk::http_type response_type = ntk::get_http_type( http_response_payload );

    ASSERT_EQ( request_type, ntk::http_type::REQUEST );
    ASSERT_EQ( response_type, ntk::http_type::RESPONSE );
}

TEST( PacketParsingTests, HttpResponseStatusLine ) {

    auto http_payload = ntk::extract_http_payload_from_ethernet( test::http_response_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    auto htpp_response_status_line = ntk::parse_http_status_line( std::get<0>( http_sections ) );

    ASSERT_EQ( htpp_response_status_line.status_code, 200 );
}