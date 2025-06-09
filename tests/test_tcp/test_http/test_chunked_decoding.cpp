#include <vector>

#include <gtest/gtest.h>

#include <http.hpp>

TEST( PacketParsingTests, HTTPChunkedBodyDecoding ) {

    std::vector<uint8_t> chunked_data = {
        '4', '\r', '\n', 'W', 'i', 'k', 'i', '\r', '\n',
        '5', '\r', '\n', 'p', 'e', 'd', 'i', 'a', '\r', '\n',
        '0', '\r', '\n', '\r', '\n'
    };

    auto actual_decoded_data = ntk::decode_chunked_http_body( chunked_data ); 

    std::vector<uint8_t> expected_decoded_data = {
        'W', 'i', 'k', 'i',
        'p', 'e', 'd', 'i', 'a'
    };

    ASSERT_EQ( expected_decoded_data, actual_decoded_data );
}