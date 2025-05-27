#ifndef HTTP_HPP
#define HTTP_HPP

#include <algorithm>

#include <cstdint>
#include <cstring>

#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>

#include <tcp.hpp>
#include <utils.hpp>

namespace ntk {

    using http_headers = std::unordered_map<std::string,std::string>;

    enum class http_type {
        REQUEST,
        RESPONSE,
        DATA
    };

    /*
        first line of a http response
    */
    struct http_response_status_line {
        std::string http_version;
        int status_code;
        std::string reason_phrase;
    };

    /*
        first line of a http request
    */
    struct http_request_line {
        std::string method_token;
        std::string path;
        std::string http_version;
    };

    std::vector<uint8_t> extract_http_payload_from_ethernet( const unsigned char* ethernet_frame );

    std::vector<uint8_t> extract_http_payload_from_tcp( const std::vector<uint8_t> tcp_frame );

    /*
        take an array of bytes obtained from extract_http_payload* and split into into three
        arrays, representing:
            request_line, headers, and body in the case of a http request and
            status_line, headers, and body in the case of http response
    */
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    split_http_payload( const std::vector<uint8_t>& payload );

    /*
        parse the request line from a http request
    */
    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes );

    bool contains_http_header( const http_headers& headers, const std::string& header_name );

    /*
        parse the status line from a http response
    */
    http_response_status_line parse_http_status_line( const std::vector<uint8_t>& status_line_bytes );

    /*
        parse headers directly from an array of bytes representing those headers
    */
    http_headers parse_http_headers( const std::vector<uint8_t>& header_bytes );

    http_headers get_http_headers_from_payload( const std::vector<uint8_t>& http_payload_bytes );
    /*stats
        determine if a http payload is a http request, a http respense or raw data
    */
    http_type get_http_type( const std::vector<uint8_t>& http_payload );

    std::vector<uint8_t> decode_single_chunk( const std::vector<uint8_t>& chunked_body );

    std::vector<uint8_t> decode_chunked_http_body( const std::vector<uint8_t>& chunked_body );

    std::vector<uint8_t> get_first_http_respone( const session& packet_data );

    std::vector<uint8_t> get_http_response_data( const tcp_stream& stream );
}

#endif