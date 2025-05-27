#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>
#include <qt.hpp>

TEST( PacketParsingTests, VisualCheckParsedText ) {

    auto http_payload = ntk::extract_http_payload_from_ethernet( test::http_response_packet );
    auto http_sections = ntk::split_http_payload( http_payload );
    auto http_content = std::get<2>( http_sections ); 

    EXPECT_FALSE( http_content.empty() );

    auto dechunked_http_content = ntk::decode_single_chunk( http_content ); 
    std::string http_content_string( dechunked_http_content.begin(), dechunked_http_content.end() );

    test::show_text_in_qt_window( QString::fromStdString( http_content_string ) );
}