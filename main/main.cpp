#include <pcap.h>

#include <iomanip>
#include <iostream>

#include <winsock2.h>

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

void packet_handler( unsigned char *user_data, 
                     const struct pcap_pkthdr *pkthdr, 
                     const unsigned char *packet) {

    unsigned char dest_mac[ 6 ];
    unsigned char src_mac[ 6 ];
                        
    std::copy( packet, packet + 6, dest_mac );
    std::cout << "Destination MAC Address: ";
    print_mac_address( dest_mac );  
    std::cout << std::endl;
                        
    std::copy( packet + 6, packet + 12, src_mac );
    std::cout << "Source MAC Address: ";
    print_mac_address( src_mac );  
    std::cout << std::endl;

    std::cout << "Packet length: " << pkthdr->len << std::endl;
    std::cout << "Timestamp: " 
              << pkthdr->ts.tv_sec << "." 
              << pkthdr->ts.tv_usec << std::endl;

    std::cout << "First 16 bytes of packet data: ";
    for ( int i = 0; i < pkthdr->len; i++ ) {
        printf( "%02x ", packet[ i ] );
    }
    std::cout << std::endl;
}

int main() {

    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[ PCAP_ERRBUF_SIZE ];

    // Find all available devices
    if ( pcap_findalldevs( &alldevs, errbuf ) == -1 ) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Available devices:" << std::endl;
    int i = 1;
    for ( device = alldevs; device != NULL; device = device->next ) {
        std::cout << i++ << ": " << device->name << " (" 
                  << ( device->description ? device->description : "No description" ) 
                  << ")" << std::endl;
    }

    // Select the device by number
    int choice;
    std::cout << "Select a device by number: ";
    std::cin >> choice;

    // Navigate to the selected device
    device = alldevs;
    for ( int j = 1; j < choice; j++ ) {
        device = device->next;
    }

    // Open the device for packet capture
    pcap_t *handle = pcap_open_live( device->name, BUFSIZ, 1, 1000, errbuf );
    if ( handle == NULL ) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Successfully opened device: " << device->name << std::endl;

    // No filter; capture all packets
    std::cout << "Capturing all packets... Press Ctrl+C to stop." << std::endl;
    if ( pcap_loop( handle, 0, packet_handler, NULL ) < 0 ) {
        std::cerr << "Error capturing packets: " << pcap_geterr( handle ) << std::endl;
    }

    pcap_close( handle );
    pcap_freealldevs( alldevs );

    return 0;
}
