#include <packet_capture.hpp>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <string>

uint16_t get_ethernet_type( const unsigned char *packet ) {
    uint16_t ethernet_type;

    std::copy( packet + 12, packet + 14, reinterpret_cast<unsigned char*>( &ethernet_type ) );
    return ntohs( ethernet_type );
}

bool is_ipv_4( uint16_t ethernet_type ) {

    return ethernet_type == 0x0800;
} 

void print_mac_address( const unsigned char* mac ) {
    for ( int i = 0; i < 6; i++ ) {
        std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ i ];
        if ( i < 5 ) {
            std::cout << ":";
        }
    }
}

int main() {

    const std::string filename = "../packet_data/color.txt";

    shark::capture_packets( filename );

    return 0;
}
