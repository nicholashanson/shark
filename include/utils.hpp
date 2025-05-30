#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>

#include <constants.hpp>
#include "tcp.hpp"

namespace ntk {

    /*
        read in a series of packets from a file that was made using packet-capture
    */
    session read_packets_from_file( const std::string& packet_data_file );

    // TODO: check http rules on whitespace in headers
    std::string trim( const std::string& str );

    inline void print_vector( const std::vector<uint8_t>& data ) {
        for ( auto byte : data ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    template<size_t n>
    void print_array( const std::array<uint8_t,n>& data ) {
        for ( auto byte : data ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    inline void print_packet_array( const unsigned char* packet_data, const size_t packet_len ) {
        for ( size_t i = 0; i < packet_len; ++i ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( packet_data[ i ] ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    inline void print_tcp_stream_info(const std::map<uint32_t, std::vector<uint8_t>>& stream ) {
        for (const auto& [seq_num, data] : stream) {
            std::cout << "Seq: " << seq_num 
                    << ", Size: " << data.size() << " bytes\n";
        }
    }

    inline void print_tcp_options( const tcp_header& header ) {
        for ( const auto& opt : header.options ) {
            std::cout << "Option kind: " << static_cast<int>( opt.type ) << " -> data bytes: ";
            for ( const auto& byte : opt.option ) {
                std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
            }
            std::cout << std::dec << std::endl;  
        }
    }

}

#endif