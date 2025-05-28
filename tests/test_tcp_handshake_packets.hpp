#ifndef TCP_HANDSHAKE_PACKETS_HPP
#define TCP_HANDSHAKE_PACKETS_HPP

namespace test_constants {

    inline const unsigned char tcp_syn_packet[] = {

        /* ethernet header */
        // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa, 
        // source mac address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,
        // ether-type
        0x08, 0x00, // 0x08 indicates ipv4
        
        /* ipv4 header */
        // version and header-length
        0x45, // version = 4, header-length = 5 * 4 = 20 bytes
        // DSCP and ECN
        0x00,
        // total length of packet
        0x00, 0x3c, 
        // identification
        0x44, 0xeb, 
        // flags and fragment offset
        0x40, 0x00, 
        // time-to-live
        0x40, 
        // protocol
        0x06, // TCP protocol
        // header checksum
        0x74, 0x57, 
        // source IP address
        0xc0, 0xa8, 0x00, 0x14, 
        // destination IP address
        0xc0, 0xa8, 0x00, 0x15,

        /* tcp header */
        // source port
        0xac, 0x18,
        // destination port
        0x0b, 0xb8,
        // sequence number
        0xb9, 0x20, 0xc9, 0xb3, 
        // acknowledgment number
        0x00, 0x00, 0x00, 0x00, 
        // data offset and reserved
        0xa0, 
        // flags ( SYN )
        0x02, 
        // window size
        0xff, 0xff, 
        // checksum
        0x17, 0x6e, 
        // urgent pointer
        0x00, 0x00, 

        /* tcp options */                                               /* tcp options */
        0x02, 0x04, 0x05, 0xb4,                                         // maximum segment size ( MSS ) = 1460
        0x04, 0x02,                                                     // selective acknowledgment permitted
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x64, 0x00, 0x00, 0x00, 0x00,     // timestamp option
        0x01,                                                           // no operation
        0x03, 0x03, 0x09                                                // window scale factor 
    };   

    inline const unsigned char tcp_synack_packet[] = {

        /* ethernet header */
        // destination mac address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,
        // source mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,
        // ether-type (IPv4)
        0x08, 0x00,
        
        /* ipv4 header */
        0x45,       // Version (4) + IHL (5)
        0x00,       // DSCP + ECN
        0x00, 0x3c, // Total Length = 60 bytes
        0x00, 0x00, // Identification
        0x40, 0x00, // Flags + Fragment Offset
        0x40,       // TTL = 64
        0x06,       // Protocol = TCP
        0xb9, 0x42, // Header checksum
        0xc0, 0xa8, 0x00, 0x15, // Source IP: 192.168.0.21
        0xc0, 0xa8, 0x00, 0x14, // Destination IP: 192.168.0.20

        /* tcp header */
        0x0b, 0xb8,             // Source port = 3000
        0xac, 0x18,             // Destination port = 44056
        0xd3, 0xc1, 0xea, 0x09, // Sequence number
        0xb9, 0x20, 0xc9, 0xb4, // Acknowledgment number
        0xa0,                   // Data offset (10) << 4 + Reserved
        0x12,                   // Flags: SYN and ACK
        0xfe, 0x88,             // Window size
        0x81, 0xa8,             // Checksum
        0x00, 0x00,             // Urgent pointer

        /* tcp options */
        0x02, 0x04, 0x05, 0xb4,                                     // MSS = 1460
        0x04, 0x02,                                                 // SACK permitted
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x69, 0x02, 0x0d, 0x72, 0x64, // Timestamp
        0x01,                                                       // NOP 
        0x03, 0x03, 0x07                                            // Window scale
    };

    inline const unsigned char tcp_ack_packet[] = {

        /* ethernet header */
        // destination MAC address (server)
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,
        // source MAC address (client)
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,
        // ether-type (IPv4)
        0x08, 0x00,

        /* ipv4 header */
        0x45,             // Version = 4, IHL = 5 (20 bytes)
        0x00,             // DSCP + ECN
        0x00, 0x34,       // Total Length = 52 bytes
        0x44, 0xec,       // Identification
        0x40, 0x00,       // Flags + Fragment Offset
        0x40,             // TTL = 64
        0x06,             // Protocol = TCP
        0x74, 0x5e,       // Header checksum
        0xc0, 0xa8, 0x00, 0x14, // Source IP: 192.168.0.20
        0xc0, 0xa8, 0x00, 0x15, // Destination IP: 192.168.0.21

        /* tcp header */
        0xac, 0x18,             // Source port = 44056
        0x0b, 0xb8,             // Destination port = 3000
        0xb9, 0x20, 0xc9, 0xb4, // Sequence number
        0xd3, 0xc1, 0xea, 0x0a, // Acknowledgment number
        0x80,                   // Data offset (8) << 4, Reserved
        0x10,                   // Flags = ACK
        0x00, 0x80,             // Window size
        0x72, 0xde,             // Checksum
        0x00, 0x00,             // Urgent pointer

        /* tcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x97, 0x58, 0x64, 0xbc, 0x69      // timestamp             
    };    

} // namespace test_constants

#endif