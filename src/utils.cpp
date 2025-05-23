#include <utils.hpp>

namespace shark {

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

}