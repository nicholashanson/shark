
#include <ipv4.hpp>

namespace shark {

    std::string trim( const std::string& str ) {
        
        size_t start = str.find_first_not_of(" \t\r\n" );
        size_t end = str.find_last_not_of(" \t\r\n" );

        return ( start == std::string::npos || end == std::string::npos )
            ? ""
            : str.substr( start, end - start + 1 );
    }

    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame ) {

        uint8_t ihl = ethernet_frame[ 14 ] & 0x0F;      
        size_t header_len = ihl * 4;         

        std::vector<uint8_t> ipv4_header( header_len );  
        std::memcpy( ipv4_header.data(), ethernet_frame + 14, header_len );

        return ipv4_header;  
    }

    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, 
                                              const size_t ipv4_header_len ) {

        std::array<uint8_t,8> udp_header;

        std::memcpy( udp_header.data(), ethernet_frame + 14 + ipv4_header_len, 8 );

        return udp_header;
    }

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame,
                                             const size_t ipv4_header_len ) {

        std::vector<uint8_t> tcp_header;

        size_t tcp_header_offset = 14 + ipv4_header_len;

        uint8_t data_offset_byte = ethernet_frame[ tcp_header_offset + 12 ];

        size_t data_offset = ( data_offset_byte >> 4 ) * 4;
        
        tcp_header.resize( data_offset );

        std::memcpy( tcp_header.data(), ethernet_frame + 14 + ipv4_header_len, data_offset );

        return tcp_header;
    }

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header ) {

        ipv4_header header;

        header.ihl = ( raw_ipv4_header[ 0 ] & 0x0F ) * 4;
        header.protocol = raw_ipv4_header[ 9 ];

        return header;
    }

    udp_header parse_udp_header( const std::array<uint8_t,8>& raw_udp_header ) {

        udp_header header;

        header.source_port = ( raw_udp_header[ 0 ] << 8 ) | raw_udp_header[ 1 ];

        return header;
    }


    tcp_header parse_tcp_header( const std::vector<uint8_t>& raw_tcp_header ) {

        if ( raw_tcp_header.size() < 20 ) {
            throw std::runtime_error( "Invalid TCP header size" );
        }

        tcp_header header;

        header.source_port = ( raw_tcp_header[ 0 ] << 8 ) | raw_tcp_header[ 1 ];

        header.destination_port = ( raw_tcp_header[ 2 ] << 8 ) | raw_tcp_header[ 3 ];

        header.sequence_number = ( raw_tcp_header[ 4 ] << 24 ) | ( raw_tcp_header[ 5 ] << 16 ) |
                                 ( raw_tcp_header[ 6 ] << 8 ) | raw_tcp_header[ 7 ];

        header.acknowledgment_number = ( raw_tcp_header[ 8 ] << 24 ) | ( raw_tcp_header[ 9 ] << 16 ) |
                                       ( raw_tcp_header[ 10 ] << 8 ) | raw_tcp_header[ 11 ];

        header.data_offset = ( raw_tcp_header[ 12 ] >> 4 ) & 0x0F;  

        header.window_size = ( raw_tcp_header[ 14 ] << 8 ) | raw_tcp_header[ 15 ];

        header.checksum = ( raw_tcp_header[ 16 ] << 8 ) | raw_tcp_header[ 17 ];

        header.urgent_pointer = ( raw_tcp_header[ 18 ] << 8 ) | raw_tcp_header[ 19 ];

        if ( header.data_offset == 5 ) 
            return header;
        
        size_t index = 20;

        size_t header_byte_length = header.data_offset * 4;

        while ( index < header_byte_length ) {

            uint8_t kind = raw_tcp_header[ index ];
    
            if ( kind == 0 ) {
                break;
            } else if ( kind == 1 ) {
                header.options.push_back( { kind, {} } );
                index += 1;
            } else {

                uint8_t length = raw_tcp_header[ index + 1 ];
    
                std::vector<uint8_t> data;

                if ( length > 2 ) {
                    data.insert( data.end(), 
                                 raw_tcp_header.begin() + index + 2,
                                 raw_tcp_header.begin() + index + length);
                }
    
                header.options.push_back( { kind, data } );

                index += length;
            }
        }

        return header;
    }

    std::vector<uint8_t> extract_http_payload( const unsigned char* ethernet_frame ) {
        
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

    http_type get_http_type( const std::vector<uint8_t>& http_payload ) {

        std::string first_five( http_payload.begin(), http_payload.begin() + 5 );


        if ( first_five.compare( 0, 5, "HTTP/" ) == 0 ) {
            return http_type::RESPONSE; 
        } else {
            return http_type::REQUEST;
        }
    }

    http_response_status_line parse_http_response_status_line( const std::vector<uint8_t>& status_line_bytes ) {

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
} // namespace shark