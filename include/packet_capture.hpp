#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <pcap.h>

#include <constants.hpp>

#include <iomanip>
#include <iostream>
#include <fstream>

namespace shark {

    inline void packet_handler( unsigned char *user_data, 
                                const struct pcap_pkthdr *pkthdr, 
                                const unsigned char *packet ) {

        unsigned char dest_mac[ 6 ];
        unsigned char src_mac[ 6 ];
                            
        std::copy( packet, packet + 6, dest_mac );
        std::copy( packet + 6, packet + 12, src_mac );

        for ( int i = 0; i < pkthdr->len; i++ ) {
            printf( "%02x ", packet[ i ] );
        }
        std::cout << std::endl;
    }

    inline void write_packet_to_file( unsigned char* user_data,
                                      const struct pcap_pkthdr* pkthdr,
                                      const unsigned char* packet ) {

        auto* file_handle = reinterpret_cast<std::ofstream*>( user_data );

        for (int i = 0; i < pkthdr->len; ++i) {
            *file_handle << std::hex << std::setw( 2 ) 
                        << std::setfill( '0' ) << static_cast<int>( packet[ i ] ) << " ";
        }
        *file_handle << std::endl;
    }

    inline pcap_if_t* list_and_select_device() {
        
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "Error finding devices: " << errbuf << std::endl;
            return nullptr;
        }

        std::cout << "Available devices:" << std::endl;
        int i = 1;
        for (pcap_if_t *device = alldevs; device != nullptr; device = device->next) {
            std::cout << i++ << ": " << device->name << " (" 
                      << (device->description ? device->description : "No description") << ")" << std::endl;
        }

        int choice;
        std::cout << "Select a device by number: ";
        std::cin >> choice;

        pcap_if_t *device = alldevs;
        for (int j = 1; j < choice; ++j) {
            if (device->next)
                device = device->next;
            else {
                std::cerr << "Invalid device choice." << std::endl;
                pcap_freealldevs(alldevs);
                return nullptr;
            }
        }

        // Note: we keep the list allocated to free later
        return device;
    }

    // Opens the selected device and returns a handle or nullptr on failure
    inline pcap_t* open_device(pcap_if_t *device) {
    
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(device->name, constants::max_snap_len, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "Error opening device: " << errbuf << std::endl;
        }
        return handle;
    }

    // Compiles and applies a filter on the pcap handle, returns true on success
    inline bool apply_filter(pcap_t *handle, const char *filter_exp) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            return false;
        }
        pcap_freecode(&fp);
        return true;
    }

    // Starts the capture loop, returns 0 on success or error code
    inline int start_capture(pcap_t *handle, std::ofstream &file_handle) {
        std::cout << "Capturing packets... Press Ctrl+C to stop." << std::endl;
        int ret = pcap_loop(handle, 0, write_packet_to_file, reinterpret_cast<u_char*>(&file_handle));
        if (ret < 0) {
            std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        }
        return ret;
    }

    // Main capture function that uses all helpers
    inline void capture_packets( const std::string& filename ) {
        std::ofstream file_handle( filename );
        if (!file_handle.is_open()) {
            std::cerr << "Failed to open output file." << std::endl;
            return;
        }

        pcap_if_t *device = list_and_select_device();
        if (!device) return;

        pcap_t *handle = open_device(device);
        if (!handle) {
            pcap_freealldevs(device);
            return;
        }

        if (!apply_filter(handle, "tcp port 3000")) {
            pcap_close(handle);
            pcap_freealldevs(device);
            return;
        }

        std::cout << "Successfully opened device: " << device->name << std::endl;

        start_capture(handle, file_handle);

        pcap_close(handle);
        pcap_freealldevs(device);
    }

} // namespace shark

#endif

