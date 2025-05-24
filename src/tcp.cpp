#include <tcp.hpp>

namespace shark {

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

    std::vector<raw_tcp_frame> extract_raw_tcp_stream( const session& tcp_session ) {

        std::vector<raw_tcp_frame> tcp_stream;

        for ( auto& packet : tcp_session ) {

            const unsigned char* packet_data = reinterpret_cast<const unsigned char*>( packet.data() );

            auto ipv4_header = extract_ipv4_header( packet_data );
            auto parsed_ipv4_header = parse_ipv4_header( ipv4_header );

            auto header = extract_tcp_header( packet_data, parsed_ipv4_header.ihl );
            auto body = extract_http_payload_from_ethernet( packet_data );

            if ( body.empty() ) {
                continue;
            }

            raw_tcp_frame frame = {
                .header = header,
                .body = body
            };

            tcp_stream.push_back( frame );
        }

        return tcp_stream;
    }

    tcp_stream get_tcp_stream( const std::vector<raw_tcp_frame>& raw_stream ) {

        tcp_stream stream;

        for ( auto& tcp_frame : raw_stream ) {
            auto parsed_tcp_header = parse_tcp_header( tcp_frame.header );
            stream[ parsed_tcp_header.sequence_number ] = tcp_frame.body;
        }

        return stream;
    } 

    bool is_non_overlapping_stream( const tcp_stream& stream ) {

        if ( stream.empty() ) return true;

        uint32_t last_end_seq = 0;
        bool first = true;

        for ( const auto& [ seq, payload ] : stream ) {

            uint32_t start_seq = seq;
            uint32_t length = static_cast<uint32_t>( payload.size() );
            uint32_t end_seq = start_seq + length;

            if ( !first && start_seq < last_end_seq ) {
                return false;
            }

            last_end_seq = end_seq;
            first = false;
        }
        return true;
    }

    tcp_stream merge_tcp_stream_non_overlapping( const tcp_stream& stream ) {

        tcp_stream merged;

        uint32_t end_of_last = 0;

        for (const auto& [ seq, data ] : stream) {
            if ( seq >= end_of_last ) {
                merged[ seq ] = data;
                end_of_last = seq + data.size();
            } else if ( seq + data.size() <= end_of_last ) {
                continue;
            } else {
                size_t overlap = end_of_last - seq;
                std::vector<uint8_t> trimmed( data.begin() + overlap, data.end() );
                merged[ end_of_last ] = trimmed;
                end_of_last += trimmed.size();
            }
        }

        return merged;
    }

    tcp_stream get_merged_tcp_stream( const session& packet_data ) {
        auto raw_stream = extract_raw_tcp_stream( packet_data );
        auto tcp_stream = get_tcp_stream( raw_stream );
        auto merged_tcp_stream = merge_tcp_stream_non_overlapping( tcp_stream );
        return merged_tcp_stream;
    }

} // namespace shark