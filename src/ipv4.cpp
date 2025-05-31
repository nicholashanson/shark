
#include <ipv4.hpp>

namespace ntk {

    std::vector<uint8_t> extract_ipv4_header( const unsigned char* ethernet_frame ) {

        uint8_t ihl = ethernet_frame[ 14 ] & 0x0F;      
        size_t header_len = ihl * 4;         

        std::vector<uint8_t> ipv4_header( header_len );  
        std::memcpy( ipv4_header.data(), ethernet_frame + 14, header_len );

        return ipv4_header;  
    }

    ipv4_header parse_ipv4_header( const std::vector<uint8_t>& raw_ipv4_header ) {

        ipv4_header header;

        header.ihl = ( raw_ipv4_header[ 0 ] & 0x0F ) * 4;
        header.total_length = ( raw_ipv4_header[ 2 ] << 8 ) | raw_ipv4_header[ 3 ];
        header.time_to_live = raw_ipv4_header[ 8 ];
        header.protocol = raw_ipv4_header[ 9 ];
        header.header_checksum = ( raw_ipv4_header[ 10 ] << 8 ) | raw_ipv4_header[ 11 ];
        
        header.source_ip_addr = ( raw_ipv4_header[ 12 ] << 24 ) |
                                ( raw_ipv4_header[ 13 ] << 16 ) |
                                ( raw_ipv4_header[ 14 ] << 8 )  |
                                  raw_ipv4_header[ 15 ];


        header.destination_ip_addr = ( raw_ipv4_header[ 16 ] << 24 ) |
                                     ( raw_ipv4_header[ 17 ] << 16 ) |
                                     ( raw_ipv4_header[ 18 ] << 8 )  |
                                       raw_ipv4_header[ 19 ];

        return header;
    }

    ipv4_header get_ipv4_header( const unsigned char* ethernet_frame ) {
        return parse_ipv4_header( extract_ipv4_header( ethernet_frame ) );
    }

    sender_reciever get_sender_reciever( const unsigned char* ethernet_frame ) {

        auto header = parse_ipv4_header( extract_ipv4_header( ethernet_frame ) );

        return std::make_pair( header.source_ip_addr, header.destination_ip_addr );
    }

    sender_reciever flip_sender_reciever( const sender_reciever& src_dest ) {

        sender_reciever dest_src;

        dest_src.first = src_dest.second;
        dest_src.second = src_dest.first;

        return dest_src;
    }

} // namespace ntk