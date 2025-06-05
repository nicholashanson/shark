#include <utils.hpp>

namespace ntk {

    std::string trim( const std::string& str ) {
        
        size_t start = str.find_first_not_of(" \t\r\n" );
        size_t end = str.find_last_not_of(" \t\r\n" );

        return ( start == std::string::npos || end == std::string::npos )
            ? ""
            : str.substr( start, end - start + 1 );
    }

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

    void print_tcp_option(const tcp_option& opt) {
        
        std::cout << "    Option[" << static_cast<int>(opt.type)
                  << "]: Type: " << static_cast<int>(opt.type) << ", Data: [";
        
        for (size_t i = 0; i < opt.option.size(); ++i) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' )
                     << static_cast<int>( opt.option[ i ] );
            if ( i != opt.option.size() - 1 )
                std::cout << " ";
        }

        std::cout << std::dec << std::setfill(' ') << "]\n";
    }

    void print_tcp_header(const tcp_header& header) {

        const int label_width = 26;

        std::cout << std::dec << std::setfill( ' ' );

        std::cout << "===== TCP HEADER BEGIN =====\n";

        auto print_field = [&]( const std::string& label, auto value ) {
            std::cout << std::left << std::setw( label_width ) << label << value << "\n";
        };

        print_field( "Source Port:", header.source_port );
        print_field( "Destination Port:", header.destination_port );
        print_field( "Sequence Number:", header.sequence_number );
        print_field( "Acknowledgment Number:", header.acknowledgment_number );
        print_field( "Data Offset:", static_cast<uint32_t>( header.data_offset ) ); 

        std::cout << std::left << std::setw( label_width ) << "Flags:"
                  << "0x" << std::hex << static_cast<int>( header.flags ) << std::dec << "\n";

        print_field( "Window Size:", header.window_size );

        std::cout << std::left << std::setw( label_width ) << "Checksum:"
                 << "0x" << std::hex << std::setw( 4 ) << std::setfill( '0' )
                 << header.checksum << std::dec << std::setfill( ' ' ) << "\n";

        print_field( "Urgent Pointer:", header.urgent_pointer );

        std::cout << std::left << std::setw( label_width ) << "Options:";
        if ( header.options.empty() ) {
            std::cout << "None\n";
        } else {
            std::cout << "\n";
            for ( const auto& opt : header.options ) {
                print_tcp_option( opt );
            }
        }

        std::cout << "===== TCP HEADER END =====\n\n";
    }

}