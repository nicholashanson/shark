#ifndef TCP_HANDSHAKE_PACKETS_HPP
#define TCP_HANDSHAKE_PACKETS_HPP

namespace test_constants {

    inline const unsigned char tcp_syn_packet[] = {
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination mac address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source mac address
        0x08, 0x00,                                                     // ether-type: 0x08 indicates ipv4
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header-length = 5 * 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x00, 0x3c,                                                     // total length of packet
        0x44, 0xeb,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x06,                                                           // TCP protocol
        0x74, 0x57,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip address  
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip address
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // source port
        0x0b, 0xb8,                                                     // destination port
        0xb9, 0x20, 0xc9, 0xb3,                                         // sequence number   
        0x00, 0x00, 0x00, 0x00,                                         // acknowledgment number
        0xa0,                                                           // data offset and reserved
        0x02,                                                           // flags ( SYN )
        0xff, 0xff,                                                     // window size
        0x17, 0x6e,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x02, 0x04, 0x05, 0xb4,                                         // maximum segment size ( MSS ) = 1460
        0x04, 0x02,                                                     // selective acknowledgment permitted
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x64, 0x00, 0x00, 0x00, 0x00,     // timestamp option
        0x01,                                                           // no operation
        0x03, 0x03, 0x09                                                // window scale factor 
    };   

    inline const unsigned char tcp_synack_packet[] = {
        /* ethernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac address
        0x08, 0x00,                                                     // ether-type ( ipv4 )
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version ( 4 ) + ihl ( 5 )
        0x00,                                                           // DSCP + ECN
        0x00, 0x3c,                                                     // total-length = 60 bytes
        0x00, 0x00,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL = 64
        0x06,                                                           // protocol = TCP
        0xb9, 0x42,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip: 192.168.0.21
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip: 192.168.0.20
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port = 3000
        0xac, 0x18,                                                     // destination port = 44056
        0xd3, 0xc1, 0xea, 0x09,                                         // sequence number
        0xb9, 0x20, 0xc9, 0xb4,                                         // acknowledgment number
        0xa0,                                                           // data offset ( 10 ) << 4 + reserved
        0x12,                                                           // flags: SYN and ACK
        0xfe, 0x88,                                                     // window size
        0x81, 0xa8,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x02, 0x04, 0x05, 0xb4,                                         // MSS = 1460
        0x04, 0x02,                                                     // SACK permitted
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x69, 0x02, 0x0d, 0x72, 0x64,     // timestamp
        0x01,                                                           // NOP 
        0x03, 0x03, 0x07                                                // window scale
    };

    inline const unsigned char tcp_ack_packet[] = {
        /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination MAC address ( server )
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source MAC address ( client ) 
        0x08, 0x00,                                                     // ether-type ( ipv4 )
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, ihl = 5 ( 20 bytes )
        0x00,                                                           // DSCP + ECN
        0x00, 0x34,                                                     // total length = 52 bytes
        0x44, 0xec,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL = 64
        0x06,                                                           // protocol = TCP
        0x74, 0x5e,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip: 192.168.0.20
        0xc0, 0xa8, 0x00, 0x15,                                         // destination IP: 192.168.0.21
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // source port = 44056
        0x0b, 0xb8,                                                     // destination port = 3000
        0xb9, 0x20, 0xc9, 0xb4,                                         // sequence number
        0xd3, 0xc1, 0xea, 0x0a,                                         // acknowledgment number
        0x80,                                                           // data offset ( 8 ) << 4, reserved
        0x10,                                                           // flags = ACK
        0x00, 0x80,                                                     // window size
        0x72, 0xde,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x97, 0x58, 0x64, 0xbc, 0x69      // timestamp             
    };    

} // namespace test_constants

#endif