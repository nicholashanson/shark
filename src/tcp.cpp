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

    bool is_syn( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_syn( header );
    }

    bool is_ack( const tcp_header& packet_tcp_header ) {
        return ( packet_tcp_header.flags & 0x10 ) != 0;
    }

    bool is_ack( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_ack( header );
    }

    bool is_syn_ack( const tcp_header& packet_tcp_header ) {
        return is_syn( packet_tcp_header ) && is_ack( packet_tcp_header );
    }

    bool is_syn_ack( const std::vector<uint8_t>& packet ) {
        tcp_header header = get_tcp_header( packet.data() );
        return is_syn_ack( header );
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

    bool flags_contains( const uint8_t header_flags, const tcp_flags flags ) {
        return ( header_flags & static_cast<uint8_t>( flags ) ) == static_cast<uint8_t>( flags );
    }

    bool is_reset( const std::vector<uint8_t>& packet ) {
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        return flags_contains( packet_tcp_header.flags, tcp_flags::RST );
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

    const std::vector<uint8_t>* get_end_of_handshake( const session& packets, 
                                                      const four_tuple& four,
                                                      const tcp_handshake& handshake ) {
        
        const std::vector<uint8_t>* end_of_handshake;

        auto syn_header = get_tcp_header( handshake.syn.data() );
        auto syn_ack_header = get_tcp_header( handshake.syn_ack.data() );
        auto ack_header = get_tcp_header( handshake.ack.data() );

        for ( size_t i = 0; i + 2 < packets.size(); ++i ) {

            auto sequ_number_1 = get_tcp_header( packets[ i ].data() ).sequence_number;
            auto sequ_number_2 = get_tcp_header( packets[ i + 1 ].data() ).sequence_number;
            auto sequ_number_3 = get_tcp_header( packets[ i + 2 ].data() ).sequence_number;

            for ( size_t i = 0; i + 3 < packets.size(); ++i ) {
                if ( sequ_number_1 == syn_header.sequence_number &&
                     sequ_number_2 == syn_ack_header.sequence_number &&
                     sequ_number_3 == ack_header.sequence_number ) {
                    end_of_handshake = &packets[ i + 2 ];
                    return end_of_handshake;
                }
            }
        }

        return nullptr;
    }

    tcp_termination get_termination( const four_tuple& four, const session& packets ) {

        std::vector<std::vector<uint8_t>> connection_packets;

        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        std::optional<std::vector<uint8_t>> fin_1;
        std::optional<std::vector<uint8_t>> ack_1; 
        std::optional<std::vector<uint8_t>> fin_2; 
        std::optional<std::vector<uint8_t>> ack_2;

        uint32_t fin_1_seq_number = std::numeric_limits<uint32_t>::max();
        uint32_t fin_2_seq_number = std::numeric_limits<uint32_t>::max();

        auto is_fin_ack = [&]( const auto& packet_tcp_header ) {
            return ( packet_tcp_header.flags & static_cast<uint8_t>( tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( tcp_flags::FIN_ACK );
        };

        for ( const auto& packet : connection_packets ) {
    
            auto packet_tcp_header = get_tcp_header( packet.data() );

            if ( is_fin_ack( packet_tcp_header ) ) {
                std::cout << "seq: " << packet_tcp_header.sequence_number << std::endl;
            }

            if ( !fin_1 && is_fin_ack( packet_tcp_header ) ) {
                fin_1 = packet;
                fin_1_seq_number = packet_tcp_header.sequence_number;
                std::cout << "fin_1_seq_number: " << fin_1_seq_number << std::endl;
                continue;
            }

            if ( !fin_2 && is_fin_ack( packet_tcp_header ) ) {
                if ( packet_tcp_header.sequence_number == fin_1_seq_number ) continue;
                fin_2 = packet;
                fin_2_seq_number = packet_tcp_header.sequence_number;
                
                if ( packet_tcp_header.acknowledgment_number == fin_1_seq_number + 1 ) {
                    ack_1 = packet;
                    std::cout << "ack_1 set by piggyback on fin_2 packet" << std::endl;
                }
                continue;
            }

            if ( fin_1 && !ack_1 ) {
                if ( is_ack( packet_tcp_header ) &&
                     packet_tcp_header.acknowledgment_number == fin_1_seq_number + 1 ) {
                    ack_1 = packet;
                    std::cout << "ack 1 set" << std::endl;
                    continue;
                }
            }

            if ( fin_2 && !ack_2 && is_ack( packet_tcp_header ) ) {
                if ( packet_tcp_header.acknowledgment_number == fin_2_seq_number + 1 ) {
                    ack_2 = packet;
                    continue;
                }
            }
        }

        if ( fin_1 && ack_1 && fin_2 && ack_2 ) {
            return tcp_termination{
                .closing_sequence = fin_ack_fin_ack{ *fin_1, *ack_1, *fin_2, *ack_2 }
            };
        }

        for ( const auto& packet : connection_packets ) {
            auto packet_tcp_header = get_tcp_header( packet.data() );
            if ( packet_tcp_header.flags & 0x04 ) { 
                return tcp_termination {
                    .closing_sequence = packet
                };
            }
        }

        return {};
    }

    std::vector<tcp_termination> get_terminations( const four_tuple& four, const session& packets ) {

        std::vector<tcp_termination> terminations;

         std::vector<std::vector<uint8_t>> connection_packets;

        for ( const auto& packet : packets ) {
            if ( is_same_connection( packet, four ) ) {
                connection_packets.push_back( packet );
            }
        }

        std::optional<std::vector<uint8_t>> fin_1;
        std::optional<std::vector<uint8_t>> ack_1; 
        std::optional<std::vector<uint8_t>> fin_2; 
        std::optional<std::vector<uint8_t>> ack_2;

        uint32_t fin_1_seq_number = std::numeric_limits<uint32_t>::max();
        uint32_t fin_2_seq_number = std::numeric_limits<uint32_t>::max();

        auto is_fin_ack = [&]( const auto& packet_tcp_header ) {
            return ( packet_tcp_header.flags & static_cast<uint8_t>( tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( tcp_flags::FIN_ACK );
        };

        auto is_ack_of_fin_ack = [&]( const auto& tcp_header, uint32_t fin_ack_seq_number ) {
            return tcp_header.acknowledgment_number == fin_ack_seq_number + 1;
        };

        for ( const auto& packet : connection_packets ) {
    
            auto packet_tcp_header = get_tcp_header( packet.data() );

            if ( !fin_1 && is_fin_ack( packet_tcp_header ) ) {
                fin_1 = packet;
                fin_1_seq_number = packet_tcp_header.sequence_number;
            } else if ( !fin_2 && is_fin_ack( packet_tcp_header ) ) {
                if ( packet_tcp_header.sequence_number == fin_1_seq_number ) continue;
                fin_2 = packet;
                fin_2_seq_number = packet_tcp_header.sequence_number;
            } else if ( fin_1 && !ack_1 && is_ack( packet_tcp_header ) && is_ack_of_fin_ack( packet_tcp_header, fin_1_seq_number ) ) {
                ack_1 = packet;
            } else if ( fin_2 && !ack_2 && is_ack( packet_tcp_header ) && is_ack_of_fin_ack( packet_tcp_header, fin_2_seq_number ) ) {
                ack_2 = packet;
            }

            if ( fin_1 && ack_1 && fin_2 && ack_2 ) {
                terminations.push_back( tcp_termination {
                    .closing_sequence = fin_ack_fin_ack{ *fin_1, *ack_1, *fin_2, *ack_2 }
                } );
                fin_1 = ack_1 = fin_2 = ack_2 = std::nullopt;
                fin_1_seq_number = fin_2_seq_number = std::numeric_limits<uint32_t>::max();
            }
        }

        for ( const auto& packet : connection_packets ) {
            auto packet_tcp_header = get_tcp_header( packet.data() );
            if ( packet_tcp_header.flags & 0x04 ) { 
                terminations.push_back( tcp_termination {
                    .closing_sequence = packet
                } );
            }
        }

        return terminations;
    }

    const std::vector<uint8_t>* get_start_of_termination( const session& packets, 
                                                          const four_tuple& four,
                                                          const tcp_termination& termination ) {
        
        if ( std::holds_alternative<fin_ack_fin_ack>( termination.closing_sequence ) ) {
            const fin_ack_fin_ack& seq = std::get<fin_ack_fin_ack>( termination.closing_sequence );

            const auto& fin_1_header = get_tcp_header( seq[ 0 ].data() );        

            for ( size_t i = 0; i < packets.size(); ++i ) {
                auto packet_header = get_tcp_header( packets[ i ].data() );
                if ( packet_header.sequence_number == fin_1_header.sequence_number ) {
                    return &packets[ i ];
                }
            }   
        } else if ( std::holds_alternative<rst>( termination.closing_sequence ) ) {
            const rst& reset = std::get<rst>( termination.closing_sequence );

            auto reset_header = get_tcp_header( reset.data() );

            for ( size_t i = 0; i < packets.size(); ++i ) {
                auto packet_header = get_tcp_header( packets[ i ].data() );
                if ( packet_header.sequence_number == reset_header.sequence_number ) {
                    return &packets[ i ];
                }
            }   
        }

        return nullptr;
    }
    
    tcp_transfer::tcp_transfer( const four_tuple& four ) 
            : m_four( four ) {} 

    void tcp_transfer::load( const session& packet_data ) {

        tcp_handshake handshake = get_handshake( m_four, packet_data );
        tcp_termination termination = get_termination( m_four, packet_data );

        m_handshake = handshake;
        m_termination = termination;

        split_stream( packet_data );
    }

    void tcp_transfer::split_stream( const session& packet_data ) {

        auto syn_header = get_tcp_header( m_handshake.syn.data() );
        auto syn_ack_header = get_tcp_header( m_handshake.syn_ack.data() );

        auto handshake_ack_ptr = get_end_of_handshake( packet_data, m_four, m_handshake );
        handshake_ack_ptr++;

        auto termination_ptr = get_start_of_termination( packet_data, m_four, m_termination );

        auto size = static_cast<size_t>( termination_ptr - handshake_ack_ptr );

        auto packet_span = std::span{ handshake_ack_ptr, size };

        for ( auto& packet : packet_span ) {
            
            if ( is_data_packet( packet ) && get_four_from_ethernet( packet ) == m_four ) {
                m_client_traffic.push_back( packet );

                std::cout << "adding traffic" << std::endl;
                continue;
            }

            if ( is_data_packet( packet ) && get_four_from_ethernet( packet ) == flip_four( m_four ) ) {
                m_server_traffic.push_back( packet );

                std::cout << "adding traffic" << std::endl;
                continue;
            }

            if ( is_ack( packet ) && get_four_from_ethernet( packet ) == m_four ) {
                m_client_acks.push_back( packet );

                std::cout << "adding ack" << std::endl;
                continue;
            }

            if ( is_ack( packet ) && get_four_from_ethernet( packet ) == flip_four( m_four ) ) {
                m_server_acks.push_back( packet );

                std::cout << "adding ack" << std::endl;
                continue;
            }
        }
    }

    const tcp_handshake& tcp_transfer_friend_helper::handshake( const tcp_transfer& t ) {
        return t.m_handshake;
    }

    const tcp_termination& tcp_transfer_friend_helper::termination( const tcp_transfer& t ) {
        return t.m_termination;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::client_acks( const tcp_transfer& t ) {
        return t.m_client_acks;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::server_acks( const tcp_transfer& t ) {
        return t.m_server_acks;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::client_traffic( const tcp_transfer& t ) {
        return t.m_client_traffic;
    }

    const std::vector<std::vector<uint8_t>>& tcp_transfer_friend_helper::server_traffic( const tcp_transfer& t ) {
        return t.m_server_traffic;
    }

    const four_tuple& tcp_transfer_friend_helper::four( const tcp_transfer& t ) {
        return t.m_four;
    }

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

    bool is_data_packet( const std::vector<uint8_t>& packet ) {

        ipv4_header packet_ip_header = get_ipv4_header( packet.data() );
        tcp_header packet_tcp_header = get_tcp_header( packet.data() );
        size_t tcp_header_len = packet_tcp_header.data_offset * 4;

        size_t payload_len = packet.size() - packet_ip_header.ihl - tcp_header_len - constants::ethernet_header_len;

        return payload_len > 0;
    }

    bool is_ack_only_packet( const std::vector<uint8_t>& packet ) {
        return !is_data_packet( packet ) && ( get_tcp_header( packet.data() ).flags & 0x10 );
    }

    bool tcp_handshake_feed::feed( const std::vector<uint8_t>& packet ) {

        auto packet_tcp_header = get_tcp_header( packet.data() );

        if ( is_syn( packet ) ) {
            reset();
            m_syn = packet;
            return true;
        }

        if ( m_syn && !m_syn_ack && is_syn_ack( packet ) &&
             packet_tcp_header.acknowledgment_number == get_tcp_header( m_syn.value().data() ).sequence_number + 1 ) {
            m_syn_ack = packet;
            return true;
        }

        if ( m_syn_ack && is_ack( packet ) &&
             packet_tcp_header.acknowledgment_number == get_tcp_header( m_syn_ack.value().data() ).sequence_number + 1 )  {
            m_ack = packet;
            return true;
        }

        return false;
    }

    bool tcp_termination_feed::feed_packet( const std::vector<uint8_t>& packet ) {

        auto packet_tcp_header = get_tcp_header( packet.data() );

        auto is_fin_ack = [&]( const auto& packet_tcp_header ) {
            return ( packet_tcp_header.flags & static_cast<uint8_t>( tcp_flags::FIN_ACK ) ) == static_cast<uint8_t>( tcp_flags::FIN_ACK );
        };

        if ( !m_fin_1 && is_fin_ack( packet_tcp_header ) ) {
            m_fin_1 = packet;
            m_fin_1_seq_number = packet_tcp_header.sequence_number;
            std::cout << "fin_1_seq_number: " << m_fin_1_seq_number << std::endl;
            return true;
        }

        if ( !m_fin_2 && is_fin_ack( packet_tcp_header ) ) {
            if ( packet_tcp_header.sequence_number == m_fin_1_seq_number ) return false;
            m_fin_2 = packet;
            m_fin_2_seq_number = packet_tcp_header.sequence_number;
            
            if ( packet_tcp_header.acknowledgment_number == m_fin_1_seq_number + 1 ) {
                m_ack_1 = packet;
                std::cout << "ack_1 set by piggyback on fin_2 packet" << std::endl;
            }
            return true;
        }

        if ( m_fin_1 && !m_ack_1 ) {
            if ( is_ack( packet_tcp_header ) &&
                    packet_tcp_header.acknowledgment_number == m_fin_1_seq_number + 1 ) {
                m_ack_1 = packet;
                std::cout << "ack 1 set" << std::endl;
                return true;
            }
        }

        if ( m_fin_2 && !m_ack_2 && is_ack( packet_tcp_header ) ) {
            if ( packet_tcp_header.acknowledgment_number == m_fin_2_seq_number + 1 ) {
                m_ack_2 = packet;
                return true;
            }
        }

        return false;
    }

    bool tcp_termination_feed::feed( const std::vector<uint8_t>& packet ) {

        bool accepted = feed_packet( packet );

        if ( !accepted ) return false;
        
        if ( m_fin_1 && m_ack_1 && m_fin_2 && m_ack_2 ) {
            m_termination.closing_sequence = fin_ack_fin_ack{ *m_fin_1, *m_ack_1, *m_fin_2, *m_ack_2 };
            m_complete = true;
        }

        return true;
    }

    tcp_live_stream::tcp_live_stream( const four_tuple& four ) 
        : m_four( four ), m_handshake_feed( four ), m_termination_feed( four ) {}

    bool tcp_live_stream::is_complete() {
        return m_termination_feed.m_complete;
    }

    void tcp_live_stream::feed( const std::vector<uint8_t>& packet ) {

        if ( is_complete() ) return;

        if ( !is_same_connection( packet, m_four ) ) return;

        bool handshake_packet = false;
        bool termination_packet = false;
        
        if ( !m_handshake_feed.m_complete ) handshake_packet = m_handshake_feed.feed( packet );

        if ( handshake_packet ) return;

        if ( !m_termination_feed.m_complete ) termination_packet = m_termination_feed.feed( packet );

        if ( termination_packet ) return;

        m_traffic.push_back( packet );
    }

} // namespace ntk