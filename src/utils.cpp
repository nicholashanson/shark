#include <utils.hpp>

namespace ntk {

    session read_packets_from_file( const std::string& packet_data_file ) {

        std::vector<std::vector<uint8_t>> packets;

        std::ifstream file_handle( packet_data_file );

        if ( !file_handle.is_open() ) {
            std::cerr << "Failed to open file: " << packet_data_file << '\n';
            return packets;
        }

        std::string line;

        while ( std::getline( file_handle, line ) ) {
            
            std::vector<uint8_t> packet;
            std::istringstream iss( line );
            std::string byte_string;

            while ( iss >> byte_string ) {
                uint8_t byte = static_cast<uint8_t>( std::stoul( byte_string, nullptr, 16 ) );
                packet.push_back( byte );
            }

            if ( !packet.empty() ) {
                packets.push_back( packet );
            }
        }

        return packets;
    }

    
    std::vector<uint8_t> parse_hex_line( const std::string& line ) {
        
        std::vector<uint8_t> bytes;
        std::istringstream iss(line);
        std::string byte_str;

        while ( iss >> byte_str ) {
            uint8_t byte = static_cast<uint8_t>( std::stoul( byte_str, nullptr, 16 ) );
            bytes.push_back( byte );
        }

        return bytes;
    }


    std::vector<std::streampos> index_line_offsets( const std::string& filename ) {

        std::ifstream file( filename );
        std::vector<std::streampos> offsets;

        if ( !file.is_open() ) {
            std::cerr << "Failed to open file: " << filename << '\n';
            return offsets;
        }

        std::string line;
        while ( file ) {
            offsets.push_back( file.tellg() );
            std::getline( file, line );
        }

        return offsets;
    }

    std::vector<std::vector<uint8_t>> get_packets_by_line_numbers( const std::string& filename,
                                                                   const std::vector<int>& line_numbers ) {
    
        std::ifstream file( filename );
        std::vector<std::vector<uint8_t>> packets;

        if ( !file.is_open() ) {
            std::cerr << "Failed to open file: " << filename << '\n';
            return packets;
        }

        auto offsets = index_line_offsets( filename );

        for ( int line_num : line_numbers ) {
            if ( line_num <= 0 || line_num > static_cast<int>( offsets.size() ) )
                continue;

            file.clear(); 
            file.seekg( offsets[ line_num - 1 ] );

            std::string line;
            std::getline( file, line );
            packets.push_back( parse_hex_line( line ) );
        }

        return packets;
    }

    void print_tcp_option( const tcp_option& opt, std::ostream& os ) {
        
        os << "    Option[" << static_cast<int>( opt.type )
           << "]: Type: " << static_cast<int>( opt.type ) << ", Data: [";
        
        for ( size_t i = 0; i < opt.option.size(); ++i ) {
            os << std::hex << std::setw( 2 ) << std::setfill( '0' )
               << static_cast<int>( opt.option[ i ] );
            if ( i != opt.option.size() - 1 )
                os << " ";
        }

        os << std::dec << std::setfill( ' ' ) << "]\n";
    }

    void print_tcp_header( const tcp_header& header, std::ostream& os ) {

        const int label_width = 26;

        os << std::dec << std::setfill( ' ' );

        os << "===== TCP HEADER BEGIN =====\n";

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        print_field( "Source Port:", header.source_port );
        print_field( "Destination Port:", header.destination_port );
        print_field( "Sequence Number:", header.sequence_number );
        print_field( "Acknowledgment Number:", header.acknowledgment_number );
        print_field( "Data Offset:", static_cast<uint32_t>( header.data_offset ) ); 

        os << std::left << std::setw( label_width ) << "Flags:"
           << "0x" << std::hex << static_cast<int>( header.flags ) << std::dec << "\n";

        print_field( "Window Size:", header.window_size );

        os << std::left << std::setw( label_width ) << "Checksum:"
           << "0x" << std::hex << std::setw( 4 ) << std::setfill( '0' )
           << header.checksum << std::dec << std::setfill( ' ' ) << "\n";

        print_field( "Urgent Pointer:", header.urgent_pointer );

        os << std::left << std::setw( label_width ) << "Options:";
        if ( header.options.empty() ) {
            os << "None\n";
        } else {
            os << "\n";
            for ( const auto& opt : header.options ) {
                print_tcp_option( opt, os );
            }
        }

        os << "===== TCP HEADER END =====\n\n";
    }

    void print_tcp_header( const std::vector<uint8_t>& packet, std::ostream& os ) {
        tcp_header packet_tcp_header = get_tcp_header( packet );
        print_tcp_header( packet_tcp_header, os );
    }

    std::ostream& operator<<( std::ostream& os, const tcp_live_stream& live_stream ) {
        os << "===== SYN HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( live_stream.m_handshake_feed.m_handshake.syn.data() ), os );
        os << "===== SYN HEADER END =====\n";
        os << "===== SYN-ACK HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( live_stream.m_handshake_feed.m_handshake.syn_ack.data() ), os );
        os << "===== SYN-ACK HEADER END =====\n";
        os << "===== ACK HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( live_stream.m_handshake_feed.m_handshake.ack.data() ), os );
        os << "===== ACK HEADER END =====\n";

        auto& closing_sequence = std::get<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence );

        os << "===== FIN_1 HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( closing_sequence[ 0 ].data() ), os );
        os << "===== FIN_1 HEADER END =====\n";
        os << "===== ACK_1 HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( closing_sequence[ 1 ].data() ), os );
        os << "===== ACK_1 HEADER END =====\n";
        os << "===== FIN_2 HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( closing_sequence[ 2 ].data() ), os );
        os << "===== FIN_2 HEADER END =====\n";
        os << "===== ACK_2 HEADER BEGIN =====\n";
        print_tcp_header( get_tcp_header( closing_sequence[ 3 ].data() ), os );
        os << "===== ACK_2 HEADER END =====\n";

        return os;
    }

    void print_client_hello( const client_hello& c_hello, std::ostream& os ) {
        const int label_width = 26;

        os << std::dec << std::setfill( ' ' );

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << "===== CLIENT HELLO BEGIN =====\n";

        print_field( "Session ID:", session_id_to_hex( c_hello.session_id ) );
        print_field( "Client Version:", c_hello.client_version );
        print_field( "Client Random:", client_random_to_hex( c_hello.random ) );

        os << "===== CLIENT HELLO END =====\n\n";
    } 

    void print_server_hello( const server_hello& s_hello, std::ostream& os ) {
        const int label_width = 26;

        os << std::dec << std::setfill( ' ' );

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << "===== SERVER HELLO BEGIN =====\n";

        print_field( "Server Random:", client_random_to_hex( s_hello.random ) );
        print_field( "Cipher Suite:", tls_cipher_suite_names.at( static_cast<cipher_suite>( s_hello.cipher_suite ) ) );

        os << "===== SERVER HELLO END =====\n\n";
    } 

    std::ostream& operator<<( std::ostream& os, const tls_live_stream& live_stream ) {
        print_client_hello( live_stream.m_client_hello, os );
        print_server_hello( live_stream.m_server_hello, os );
        return os;
    }

    void print_four( const four_tuple& four, std::ostream& os ) {

        const int label_width = 26;

        os << std::dec << std::setfill( ' ' );

        os << "===== FOUR TUPLE BEGIN =====\n";

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        print_field( "Client IP:", four.client_ip );
        print_field( "Server IP:", four.server_ip );
        print_field( "Client Port:", four.client_port );
        print_field( "Server Port:", four.server_port );

        os << "===== FOUR TUPLE END =====\n\n";
    }

    void output_packet( const std::vector<uint8_t> packet, std::ofstream& ofs ) {
        for ( size_t i = 0; i < packet.size(); ++i ) {
            ofs << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet[ i ] );
            if ( i != packet.size() - 1 ) {
                ofs << ' ';
            }
        }
        ofs << '\n';
    };

    void output_stream_to_file( const std::string& filename, const tcp_live_stream& live_stream ) {
        std::ofstream ofs( filename );
        if ( !ofs ) {
            throw std::runtime_error( "Failed to open output file: " + filename );
        }

        auto print_packet = [&]( const std::vector<uint8_t> packet ) {
            for ( size_t i = 0; i < packet.size(); ++i ) {
                ofs << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet[ i ] );
                if ( i != packet.size() - 1 ) {
                    ofs << ' ';
                }
            }
            ofs << '\n';
        };

        const auto& handshake = live_stream.m_handshake_feed.m_handshake;

        std::vector<std::vector<uint8_t>> handshake_packets = { handshake.syn, handshake.syn_ack, handshake.ack };

        for ( const auto& packet : handshake_packets ) {
            print_packet( packet );
        }

        for ( const auto& packet : live_stream.m_traffic ) {
            print_packet( packet );
        }

        if ( std::holds_alternative<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence ) ) {
            for ( const auto& packet : std::get<fin_ack_fin_ack>( live_stream.m_termination_feed.m_termination.closing_sequence ) ) {
                print_packet( packet );
            }
        }
    }

    void print_tls_record( const tls_record& record ) {

        const int label_width = 26;

        std::cout << std::dec << std::setfill( ' ' );

        std::cout << "===== TLS RECORD BEGIN =====\n";

        auto print_field = [&]( const std::string& label, auto value ) {
            std::cout << std::left << std::setw( label_width ) << label << value << "\n";
        };

        print_field( "Content Type:", tls_content_type_names.at( record.content_type ) );
        print_field( "Version:", record.version );

        std::cout << "===== TLS RECORD END =====\n\n";
    }

    void print_tls_secrets( const secrets& keys ) {

        const int label_width = 40;

        std::cout << std::dec << std::setfill( ' ' );

        auto print_field = [&]( const std::string& label, auto value ) {
            std::cout << std::left << std::setw( label_width ) << label << value << "\n";
        };

        for ( auto [ client_random, secret ] : keys ) {
            std::cout << "===== TLS SECRETS BEGIN "
                      << client_random
                      << " =====\n";
            for ( auto& label : tls_secret_labels ) {
                print_field( label, string_to_hex( secret[ label ] ) );
            }
            std::cout << "===== TLS SECRETS END =====\n\n";
        }
    }

    std::string four_to_string( const four_tuple& four ) {
        return ip_to_string( four.client_ip ) + "_" +
               std::to_string( four.client_port ) + "_" +
               ip_to_string( four.server_ip ) + "_" +
               std::to_string( four.server_port) ;
    }

    void print_http_request( const http_request& request, std::ostream& os ) {

        const int label_width = 20;

        os << std::left << std::setfill(' ');

        os << "===== HTTP REQUEST BEGIN =====\n";

        os << request.request_line.method_token << " "
           << request.request_line.path << " "
           << request.request_line.http_version << "\n\n";

        if ( request.headers.empty() ) {
            os << "No Headers\n";
        } else {
            for ( const auto& [ key, value ] : request.headers ) {
                os << std::left << std::setw( label_width ) << ( key + ":" ) << value << "\n";
            }
        }

        os << "===== HTTP REQUEST END =====\n\n";
    }

    void print_http_response( const http_response& response, std::ostream& os ) {

        const int label_width = 40;

        os << std::left << std::setfill(' ');

        os << "===== HTTP RESPONSE BEGIN =====\n";

        os << response.status_line.http_version << " "
           << response.status_line.status_code << " "
           << response.status_line.reason_phrase << "\n\n";

        if ( response.headers.empty() ) {
            os << "No Headers\n";
        } else {
            for ( const auto& [ key, value ] : response.headers ) {
                os << std::left << std::setw( label_width ) << ( key + ":" ) << value << "\n";
            }
        }

        os << std::left << std::setw( label_width ) << "Payload_Length: " << response.body.size() << "\n";

        os << "===== HTTP RESPONSE END =====\n\n";
    };

    void write_payload_to_file( const std::vector<uint8_t>& payload, const std::string& filename ) {
        std::ofstream out( filename, std::ios::binary );
        if ( !out ) {
            throw std::runtime_error( "Failed to open file for writing: " + filename );
        }
        out.write( reinterpret_cast<const char*>( payload.data() ), payload.size() );
    }

} // namespace ntk


    