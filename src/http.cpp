#include <http.hpp>

namespace shark {

    http_type get_http_type( const std::vector<uint8_t>& http_payload ) {

        std::string first_five( http_payload.begin(), http_payload.begin() + 5 );

        if ( first_five.compare( 0, 5, "HTTP/" ) == 0 ) {
            return http_type::RESPONSE; 
        } else if ( first_five.compare( 0, 3, "GET" ) == 0 ) {
            return http_type::REQUEST;
        } else {
            return http_type::DATA;
        }
    }

    std::vector<uint8_t> extract_http_payload_from_ethernet( const unsigned char* ethernet_frame ) {
        
        const size_t ethernet_header_len = 14;

        uint8_t ihl = ethernet_frame[ ethernet_header_len ] & 0x0F;
        size_t ipv4_header_len = ihl * 4;

        uint16_t total_length = ( ethernet_frame[ ethernet_header_len + 2 ] << 8 ) |
                                  ethernet_frame[ ethernet_header_len + 3 ];

        size_t tcp_header_offset = ethernet_header_len + ipv4_header_len;

        uint8_t data_offset_byte = ethernet_frame[ tcp_header_offset + 12 ];
        size_t tcp_header_len = ( ( data_offset_byte >> 4 ) & 0x0F ) * 4;

        uint16_t src_port = ( ethernet_frame[ tcp_header_offset ] << 8 ) | ethernet_frame[ tcp_header_offset + 1 ];
        uint16_t dst_port = ( ethernet_frame[ tcp_header_offset + 2 ] << 8 ) | ethernet_frame[ tcp_header_offset + 3 ];

        size_t http_payload_len = total_length - ipv4_header_len - tcp_header_len;

        const uint8_t* http_payload_ptr = ethernet_frame + tcp_header_offset + tcp_header_len;

        std::vector<uint8_t> http_payload( http_payload_len );
        std::memcpy( http_payload.data(), http_payload_ptr, http_payload_len );

        return http_payload;
    }

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    split_http_payload( const std::vector<uint8_t>& payload ) {

        auto begin = payload.begin();
        auto end = payload.end();

        auto request_line_end = std::search( begin, end, "\r\n", "\r\n" + 2 );
        std::vector<uint8_t> request_line( begin, request_line_end );

        auto headers_start = request_line_end + 2; 
        auto headers_end = std::search( headers_start, end, "\r\n\r\n", "\r\n\r\n" + 4 );
        std::vector<uint8_t> headers( headers_start, headers_end );
        
        auto body_start = headers_end + 4; 
        std::vector<uint8_t> body( body_start, end );

        return { request_line, headers, body };
    }

    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes ) {

        std::string request_line_string( request_line_bytes.begin(), request_line_bytes.end() );

        std::stringstream request_line_stream( request_line_string );

        http_request_line r_line;

        request_line_stream >> r_line.method_token >> r_line.path >> r_line.http_version;

        return r_line;
    }

    bool contains_http_header( const http_headers& headers, const std::string& header_name  ) {
        return headers.contains( header_name );
    }  

    http_headers parse_http_headers(const std::vector<uint8_t>& header_bytes) {
        
        std::string headers_string( header_bytes.begin(), header_bytes.end() );
        
        http_headers headers;

        size_t pos = 0;

        while ( pos < headers_string.size() ) {
            
            size_t line_end = headers_string.find( "\r\n", pos );

            std::string line;

            if ( line_end == std::string::npos ) {
                line = headers_string.substr( pos );
                pos = headers_string.size();
            } else {
                line = headers_string.substr( pos, line_end - pos );
                pos = line_end + 2; 
            }

            size_t colon_pos = line.find(':');

            std::string key = trim( line.substr( 0, colon_pos ) );
            std::string value = trim( line.substr( colon_pos + 1 ) );

            headers[ key ] = value;
        }

        return headers;
    }

    http_headers get_http_headers_from_payload( const std::vector<uint8_t>& http_payload_bytes ) {

        auto http_header_bytes = std::get<1>( split_http_payload( http_payload_bytes ) );
        return parse_http_headers( http_header_bytes );
    }

    http_response_status_line parse_http_status_line( const std::vector<uint8_t>& status_line_bytes ) {

        std::string line( status_line_bytes.begin(), status_line_bytes.end() );

        std::istringstream stream(line);
        
        http_response_status_line status_line;

        stream >> status_line.http_version;

        std::string status_code_string;
        stream >> status_code_string;
        status_line.status_code = std::stoi( status_code_string );

        std::string reason_phrase;
        std::getline( stream, reason_phrase );

        status_line.reason_phrase = trim(reason_phrase);

        return status_line;
    }

    std::vector<uint8_t> decode_single_chunk( const std::vector<uint8_t>& chunked_body ) {

        auto it = std::search( chunked_body.begin(), chunked_body.end(), "\r\n", "\r\n" + 2 );
        size_t chunk_size = std::stoul( std::string( chunked_body.begin(), it ), nullptr, 16 );
        auto data_start = it + 2;

        return std::vector<uint8_t>( data_start, data_start + chunk_size );
    }

    std::vector<uint8_t> decode_chunked_http_body( const std::vector<uint8_t>& chunked_body ) {
            
        std::vector<uint8_t> decoded;
        size_t pos = 0;

        while (pos < chunked_body.size()) {

            auto crlf = std::search( chunked_body.begin() + pos, chunked_body.end(), "\r\n", "\r\n" + 2 );
            if ( crlf == chunked_body.end() ) break;

            std::string chunk_size_str( chunked_body.begin() + pos, crlf );
            size_t chunk_size = std::stoul( chunk_size_str, nullptr, 16 );
            
            pos = crlf - chunked_body.begin() + 2;

            if ( chunk_size == 0 ) break;
            if ( pos + chunk_size > chunked_body.size() ) break;
            
            decoded.insert( decoded.end(), chunked_body.begin() + pos, chunked_body.begin() + pos + chunk_size );
            
            pos += chunk_size + 2;  
        }

        return decoded;
    }

    std::vector<uint8_t> get_first_http_respone( const session& packet_data ) {

        auto raw_tcp_stream = extract_raw_tcp_stream( packet_data );
        auto tcp_stream = get_tcp_stream( raw_tcp_stream ); 

        auto response = *std::find_if( tcp_stream.begin(), tcp_stream.end(), 
            []( const auto& pair ) { 
                auto& [ unused, http_payload ] = pair;
                return shark::get_http_type( http_payload ) == shark::http_type::RESPONSE;
            } 
        );

        return response.second;
    }   

    std::vector<uint8_t> get_http_response_data( const tcp_stream& stream ) {

        auto response_pos = std::find_if( stream.begin(), stream.end(), 
            []( const auto& pair ) { 
                auto& [ unused, http_payload ] = pair;
                return shark::get_http_type( http_payload ) == shark::http_type::RESPONSE;
            } 
        );

        auto response = *response_pos;

        auto http_headers = get_http_headers_from_payload( response.second );

        auto response_data = std::get<2>( split_http_payload( response.second ) );

        auto it = std::next( response_pos );

        while ( it != stream.end() ) {
            response_data.insert( response_data.end(),
                it->second.begin(), it->second.end() );
            ++it;
        }

        if ( contains_http_header( http_headers, "Content-Length" ) ) {
            return response_data;
        } else {
            return decode_chunked_http_body( response_data );
        }
    }

} // namespace shark