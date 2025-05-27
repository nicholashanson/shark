#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>

namespace ntk {

    /*
        a "session" is a series of packets that together make-up some kind of communication
        or data-transfer
        
        e.g. transfer of an image using http over tcp
    */
    using session = std::vector<std::vector<uint8_t>>;

    /*
        read in a series of packets from a file that was made using packet-capture
    */
    session read_packets_from_file( const std::string& packet_data_file );

    // TODO: check http rules on whitespace in headers
    std::string trim( const std::string& str );
}

#endif