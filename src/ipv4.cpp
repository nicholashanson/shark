
#include <ipv4.hpp>

namespace shark {

    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame ) {

        uint8_t ihl = ethernet_frame[ 14 ] & 0x0F;      
        size_t header_len = ihl * 4;         

        std::vector<uint8_t> ipv4_header( header_len );  
        std::memcpy( ipv4_header.data(), ethernet_frame + 14, header_len );

        return ipv4_header;  
    }

    std::array<uint8_t,8> extract_udp_header( const unsigned char* ethernet_frame, 
                                              const size_t ipv4_header_len ) {

        std::array<uint8_t,8> udp_header;

        std::memcpy( udp_header.data(), ethernet_frame + 14 + ipv4_header_len, 8 );

        return udp_header;
    }

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header ) {

        ipv4_header header;

        header.ihl = ( raw_ipv4_header[ 0 ] & 0x0F ) * 4;
        header.protocol = raw_ipv4_header[ 9 ];

        return header;
    }

} // namespace shark