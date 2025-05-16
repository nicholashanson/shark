#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>

namespace shark {

    using session = std::vector<std::vector<uint8_t>>;

    session read_packets_from_file( const std::string& packet_data_file );
}

#endif