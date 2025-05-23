#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <cstddef>

namespace shark {

    namespace constants {

        // protocols
        const size_t ethernet_header_len = 14;
        const size_t udp_header_len = 8;

        // packet-capture
        const size_t max_snap_len = 65535; 
    
    } // namespace constants

} // namespace shark

#endif