#include <udp.hpp>

namespace shark {

    std::array<uint8_t,constants::udp_header_len> extract_udp_header( const unsigned char* ethernet_frame, 
                                                                      const size_t ipv4_header_len ) {

        std::array<uint8_t,8> udp_header;
        std::memcpy( udp_header.data(), ethernet_frame + 14 + ipv4_header_len, 8 );
        return udp_header;
    }

    udp_header parse_udp_header( const std::array<uint8_t,constants::udp_header_len>& raw_udp_header ) {

        udp_header header;
        header.source_port = ( raw_udp_header[ 0 ] << 8 ) | raw_udp_header[ 1 ];
        return header;
    }

} // namespace shark