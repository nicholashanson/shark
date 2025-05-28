#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

#include <map>
#include <vector>

namespace ntk {

    using tcp_stream = std::map<uint32_t,std::vector<uint8_t>>; 

    /*
        a "session" is a series of packets that together make-up some kind of communication
        or data-transfer
        
        e.g. transfer of an image using http over tcp
    */
    using session = std::vector<std::vector<uint8_t>>;

    namespace constants {

        // protocols
        const size_t ethernet_header_len = 14;
        const size_t udp_header_len = 8;

        // packet-capture
        const size_t max_snap_len = 65535; 
    
    } // namespace constants

} // namespace ntk

#endif