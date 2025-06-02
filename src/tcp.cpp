#include <tcp.hpp>

namespace ntk {

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

        header.data_offset = ( raw_tcp_header[ 12 ] >> 4 ) & 0x0f;  

        header.flags = raw_tcp_header[ 13 ];

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

    tcp_header get_tcp_header( const unsigned char* ethernet_frame ) {

        ipv4_header header = get_ipv4_header( ethernet_frame );

        return parse_tcp_header( extract_tcp_header( ethernet_frame, header.ihl ) );
    }

    std::vector<raw_tcp_frame> extract_raw_tcp_stream( const session& tcp_session ) {

        std::vector<raw_tcp_frame> tcp_stream;

        for ( auto& packet : tcp_session ) {

            const unsigned char* packet_data = reinterpret_cast<const unsigned char*>( packet.data() );

            auto ipv4_header = extract_ipv4_header( packet_data );
            auto parsed_ipv4_header = parse_ipv4_header( ipv4_header );

            auto header = extract_tcp_header( packet_data, parsed_ipv4_header.ihl );
            auto body = extract_payload_from_ethernet( packet_data );

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

    std::vector<uint8_t> extract_payload_from_ethernet( const unsigned char* ethernet_frame ) {
        
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

        size_t payload_len = total_length - ipv4_header_len - tcp_header_len;

        const uint8_t* payload_ptr = ethernet_frame + tcp_header_offset + tcp_header_len;

        std::vector<uint8_t> payload( payload_len );
        std::memcpy( payload.data(), payload_ptr, payload_len );

        return payload;
    }

    bool is_tcp( const unsigned char* packet ) {

        auto header = get_ipv4_header( packet );

        return static_cast<protocol>( header.protocol ) == protocol::TCP;
    }

    bool is_tcp_v( const std::vector<uint8_t>& packet ) {
        return is_tcp( packet.data() );
    }

    bool is_same_connection( const ipv4_header& packet_ip_header, const tcp_header& packet_tcp_header, const four_tuple& four )  { 
        return ( packet_ip_header.source_ip_addr == four.client_ip ) || ( packet_ip_header.destination_ip_addr == four.client_ip ) &&
               ( packet_ip_header.source_ip_addr == four.server_ip ) || ( packet_ip_header.destination_ip_addr == four.server_ip ) &&
               ( packet_tcp_header.source_port == four.client_port ) || ( packet_tcp_header.destination_port == four.client_port ) &&
               ( packet_tcp_header.source_port == four.server_port ) || ( packet_tcp_header.destination_port == four.server_port );
    }

    bool is_same_connection( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );

        return is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    bool is_syn( const tcp_header& packet_tcp_header ) {
        return ( packet_tcp_header.flags & 0x02 ) != 0;
    }

    bool is_ack( const tcp_header& packet_tcp_header ) {
        return ( packet_tcp_header.flags & 0x10 ) != 0;
    }

    bool is_syn_ack( const tcp_header& packet_tcp_header ) {
        return is_syn( packet_tcp_header ) && is_ack( packet_tcp_header );
    }

    bool is_syn_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );

        return is_syn( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    bool is_syn_ack_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {

        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );
        
        return is_syn_ack( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    bool is_ack_of( const std::vector<uint8_t>& packet, const four_tuple& four ) {

        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );

        return is_ack( packet_tcp_header ) && is_same_connection( packet_ip_header, packet_tcp_header, four );
    }

    tcp_handshake get_handshake( const four_tuple& four, const session& packets ) {
        
        tcp_handshake handshake;

        std::vector<std::vector<uint8_t>> connection_packets;
        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        for ( size_t i = 0; i + 2 < connection_packets.size(); ++i ) {
            const auto& syn_pkt = connection_packets[ i ];
            const auto& syn_ack_pkt = connection_packets[ i + 1 ];
            const auto& ack_pkt = connection_packets[ i + 2 ];

            if ( is_syn_of( syn_pkt, four ) &&
                 is_syn_ack_of( syn_ack_pkt, four ) &&
                 is_ack_of( ack_pkt, four ) ) {
                handshake.syn = syn_pkt;
                handshake.syn_ack = syn_ack_pkt;
                handshake.ack = ack_pkt;
                return handshake;
            }
        }

        return {}; 
    }

    std::vector<tcp_handshake> get_handshakes( const four_tuple& four, const session& packets ) {
        
        std::vector<tcp_handshake> handshakes;

        std::vector<std::vector<uint8_t>> connection_packets;
        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        for ( size_t i = 0; i + 2 < connection_packets.size(); ++i ) {
            const auto& syn_pkt = connection_packets[ i ];
            const auto& syn_ack_pkt = connection_packets[ i + 1 ];
            const auto& ack_pkt = connection_packets[ i + 2 ];

            if ( is_syn_of( syn_pkt, four ) &&
                 is_syn_ack_of( syn_ack_pkt, four ) &&
                 is_ack_of( ack_pkt, four ) ) {
                tcp_handshake handshake;
                handshake.syn = syn_pkt;
                handshake.syn_ack = syn_ack_pkt;
                handshake.ack = ack_pkt;
                handshakes.push_back( handshake );
            }
        }

        return handshakes; 
    }

    tcp_termination get_termination( const four_tuple& four, const session& packets ) {

        std::vector<std::vector<uint8_t>> connection_packets;


        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        for ( size_t i = 0; i + 3 < connection_packets.size(); ++i ) {
            const auto& fin1 = connection_packets[ i ];
            const auto& ack1 = connection_packets[ i + 1 ];
            const auto& fin2 = connection_packets[ i + 2 ];
            const auto& ack2 = connection_packets[ i + 3 ];

            auto tcp1 = get_tcp_header( fin1.data() );
            auto tcp2 = get_tcp_header( ack1.data() );
            auto tcp3 = get_tcp_header( fin2.data() );
            auto tcp4 = get_tcp_header( ack2.data() );

            if ( ( tcp1.flags & 0x01 ) && is_ack( tcp2 ) &&
                 ( tcp3.flags & 0x01 ) && is_ack( tcp4 ) ) {
                return tcp_termination {
                    .closing_sequence = fin_ack_fin_ack{ fin1, ack1, fin2, ack2 }
                };
            }
        }

        for ( const auto& packet : connection_packets ) {
            auto tcp = get_tcp_header( packet.data() );
            if ( tcp.flags & 0x04 ) { 
                return tcp_termination {
                    .closing_sequence = packet
                };
            }
        }

        return {};
    }

    class tcp_transfer {

        public:
        tcp_transfer( uint32_t client_ip, uint32_t server_ip, uint16_t server_port, uint16_t client_port )
            : client_ip( client_ip ), server_ip( server_ip ) {} 

        tcp_transfer( const four_tuple& four ) 
            : client_ip( four.client_ip ), server_ip( four.server_ip ), server_port( four.server_port ), client_port( four.client_port ) {} 

        private:
            tcp_handshake handshake;
            tcp_termination termination;
            std::vector<std::vector<uint8_t>> client_acks;
            std::vector<std::vector<uint8_t>> server_acks;
            std::vector<std::vector<uint8_t>> client_traffic;
            std::vector<std::vector<uint8_t>> server_traffic;
            
            uint32_t client_ip;
            uint32_t server_ip;

            uint16_t client_port;
            uint16_t server_port;
    };

    four_tuple flip_four( const four_tuple& four ) {
        four_tuple flipped;

        flipped.client_ip = four.server_ip;
        flipped.server_ip = four.client_ip;
        flipped.server_port = four.client_port;
        flipped.client_port = four.server_port;

        return flipped;
    }

    four_tuple get_four_from_ethernet( const std::vector<uint8_t>& packet ) {
        return get_four_from_ethernet( packet.data() );
    }

    four_tuple get_four_from_ethernet( const unsigned char* packet ) {

        tcp_header packet_tcp_header = get_tcp_header( packet );
        ipv4_header packet_ip_header = get_ipv4_header( packet );

        return four_tuple {
            .client_ip = packet_ip_header.source_ip_addr,
            .server_ip = packet_ip_header.destination_ip_addr,
            .client_port = packet_tcp_header.source_port,
            .server_port = packet_tcp_header.destination_port
        };
    }

    std::unordered_set<four_tuple> get_four_tuples( const session& packets ) {

        std::unordered_set<four_tuple> four_tuples;

        for ( auto& packet : packets ) {
            auto four = get_four_from_ethernet( packet );
            auto flipped = flip_four( four );
            if ( four_tuples.contains( four ) || four_tuples.contains( flipped ) ) {
                continue;
            }
            four_tuples.insert( four );
        }
        
        return four_tuples;
    }

} // namespace ntk