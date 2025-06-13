#ifndef TEST_CONSTANTS
#define TEST_CONSTANTS

namespace test {

    inline std::string packet_data_dir = "../packet_data";

    inline std::map<std::string,std::string> packet_data_files = {
        { "lena", packet_data_dir + "/lena.txt" },
        { "checkerboard", packet_data_dir + "/checkerboard.txt" },
        { "color", packet_data_dir + "/color.txt" },
        { "tiny_cross", packet_data_dir + "/tiny_cross.txt" },
        { "tls_handshake", packet_data_dir + "/tls_handshake.txt" },
        { "earth_cam_live_stream", packet_data_dir + "/earth_cam_live_stream.txt" },
        { "earth_cam_video", packet_data_dir + "/earth_cam_video.txt" },
        { "earth_cam_static", packet_data_dir + "/static_earth_cam.txt" },
        { "short_stream", packet_data_dir + "/192.168.0.21_48662_204.107.64.57_443.txt" },
        { "long_stream", packet_data_dir + "/192.168.0.21_48658_204.107.64.57_443.txt" }
    };

    //inline const unsigned char http_partial_request[] = {}

    inline const unsigned char mp4_meta_data[] = {
        /* ftyp box ( file type box ) */                                /* ftyp box ( file type box ) */
        0x00, 0x00, 0x00, 0x20,                                         // length : 32 bytes
        0x66, 0x74, 0x79, 0x70,                                         // ftyp
        0x69, 0x73, 0x6f, 0x6d,                                         // major brand : isom
        0x00, 0x00, 0x02, 0x00,                                         // minor version                  
        /* compatible brands */                                         /* compatible brands */
        0x69, 0x73, 0x6f, 0x6d,                                         // isom: ISO Base Media File Format  
        0x69, 0x73, 0x6f, 0x32,                                         // iso2: ISO BMFF Version 2
        0x61, 0x76, 0x63, 0x31,                                         // avc1: AVC/H.264 video
        0x6d, 0x70, 0x34, 0x31,                                         // mp41: MPEG-4 version 1
        /* moov Box */                                                  /* moov Box */
        0x00, 0x00, 0x00, 0x6c,                                         // size: 108 bytes
        0x6d, 0x6f, 0x6f, 0x76,                                         // moov Box ( Movie Box )
        0x6d, 0x76, 0x68, 0x64,                                         // mvhd
        0x00,                                                           // version
        0x00, 0x00, 0x00,                                               // flags
        0x00, 0x00, 0x00, 0x00,                                         // creation time
        0x00, 0x00, 0x00, 0x00,                                         // modification time
        0x00, 0x00, 0x03, 0xe8,                                         // timescale = 1000
        0x00, 0x02, 0x79, 0xe9,                                         // duration = 162,153
        /* rate ( 16.16 fixed ) = 1.0 */                                
        0x00, 0x01, 0x00, 0x00,                                         
        /* volume ( 8.8 fixed ) = 1.0 */                                
        0x01, 0x00,                                                     
        /* reserved 2 bytes */                                          
        0x00, 0x00,                                                     
        /* reserved 8 bytes ( 2 × 4 bytes ) */                          
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        /* matrix structure ( 36 bytes ) */                             /* matrix structure ( 36 bytes ) */
        0x00, 0x01, 0x00, 0x00,                                         // [0][0] = 1.0
        0x00, 0x00, 0x00, 0x00,                                         // [0][1] = 0.0
        0x00, 0x00, 0x00, 0x00,                                         // [0][2] = 0.0
        0x00, 0x01, 0x00, 0x00,                                         // [1][0] = 1.0 
        0x00, 0x00, 0x00, 0x00,                                         // [1][1] = 0.0
        0x00, 0x00, 0x00, 0x00,                                         // [1][2] = 0.0
        0x00, 0x00, 0x40, 0x00,                                         // [2][0] = 16384 (fixed-point)
        0x00, 0x00, 0x00, 0x00,                                         // [2][1] = 0
        0x00, 0x00, 0x00, 0x00,                                         // [2][2] = 0
        /* pre-defined ( reserved 24 bytes ) */                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                                                     
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        /* next track ID */
        0x00, 0x00, 0x03, 0x00                                              
    };                                                                  

    inline const unsigned char http_get_packet[] = {                    
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination MAC address ( server )
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source MAC address ( client )
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version ( 4 ) + ihl ( 5 )
        0x00,                                                           // DSCP + ECN
        0x01, 0x96,                                                     // total-length: 406 bytes
        0x44, 0xed,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL
        0x06,                                                           // protocol ( TCP )
        0x72, 0xfb,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip: 192.168.0.20
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip: 192.168.0.21
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // Source port: 44056
        0x0b, 0xb8,                                                     // destination port: 3000
        0xb9, 0x20, 0xc9, 0xb4,                                         // sequence number
        0xd3, 0xc1, 0xea, 0x0a,                                         // acknowledgment number
        0x80,                                                           // data offset ( 8 ) << 4, reserved
        0x18,                                                           // flags: PSH + ACK
        0x00, 0x80,                                                     // window size
        0x4b, 0x81,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* trcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x9a, 0x58, 0x64, 0xbc, 0x69,     // timestamp            
        /* HTTP GET request */                                          /* HTTP GET request */
        // Request Line: "GET / HTTP/1.1\r\n"                           // Request Line: "GET / HTTP/1.1\r\n"   
        0x47, 0x45, 0x54,                                               // GET
        0x20,                                                           // ( space )
        0x2f,                                                           // /
        0x20,                                                           // ( space )
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x2f,                                                           // /
        0x31, 0x2e, 0x31,                                               // 1.1    
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Host: 192.168.0.21:3000\r\n"                        // Header: "Host: 192.168.0.21:3000\r\n"                        
        0x48, 0x6f, 0x73, 0x74,                                         // Host
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x31, 0x39, 0x32, 0x2e,                                         // 192. 
        0x31, 0x36, 0x38, 0x2e,                                         // 168.
        0x30, 0x2e, 0x32, 0x31,                                         // 0.21
        0x3a,                                                           // :
        0x33, 0x30, 0x30, 0x30,                                         // 3000
        0x0d, 0x0a,                                                     // \r\n
        // Header: "User-Agent: Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/112.0 Firefox/112.0\r\n"
        0x55, 0x73, 0x65, 0x72,                                         // User
        0x2d,                                                           // -
        0x41, 0x67, 0x65, 0x6e, 0x74,                                   // Agent
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61,                       // Mozilla
        0x2f,                                                           // /
        0x35, 0x2e, 0x30,                                               // 5.0
        0x20,                                                           // ( space )
        0x28,                                                           // (
        0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64,                       // Android
        0x20,                                                           // ( space )
        0x31, 0x34,                                                     // 14   
        0x3b,                                                           // ;
        0x20,                                                           // ( space )
        0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65,                             // Mobile
        0x3b,                                                           // ;
        0x20,                                                           // ( space )
        0x72, 0x76, 0x3a, 0x31, 0x30, 0x39, 0x2e, 0x30,                 // rv:109.0
        0x29,                                                           // )
        0x20,                                                           // ( space )
        0x47, 0x65, 0x63, 0x6b, 0x6f,                                   // Gecko
        0x2f,                                                           // /
        0x31, 0x31, 0x32, 0x2e, 0x30,                                   // 112.0
        0x20,                                                           // ( space )
        0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78,                       // Firefox
        0x2f,                                                           // /
        0x31, 0x31, 0x32, 0x2e, 0x30,                                   // 112.0
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x3a,                                                           // ; 
        0x20,                                                           // ( space )
        0x74, 0x65, 0x78, 0x74,                                         // text
        0x2f,                                                           // /
        0x68, 0x74, 0x6d, 0x6c,                                         // "html
        0x2c,                                                           // ,
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,                             // applic
        0x61, 0x74, 0x69, 0x6f, 0x6e,                                   // ation
        0x2f,                                                           // /
        0x78, 0x68, 0x74, 0x6d, 0x6c,                                   // xhtml
        0x2b,                                                           // +
        0x78, 0x6d, 0x6c,                                               // xml
        0x2c,                                                           // ,
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,                             // applica
        0x61, 0x74, 0x69, 0x6f, 0x6e,                                   // ation
        0x2f,                                                           // /
        0x78, 0x6d, 0x6c,                                               // xml
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39,                             // ;q=0.9
        0x2c,                                                           // ,
        0x69, 0x6d, 0x61, 0x67, 0x65,                                   // image
        0x2f,                                                           //
        0x61, 0x76, 0x69, 0x66,                                         // avif
        0x2c,                                                           // ,
        0x69, 0x6d, 0x61, 0x67, 0x65,                                   // image                       
        0x2f,                                                           // /
        0x77, 0x65, 0x62, 0x70,                                         // webp
        0x2c,                                                           // ,
        0x2a, 0x2f, 0x2a,                                               // */*
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x38,                             // ;q=0.8"
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Accept-Language:                                    // Header: "Accept-Language: 
        // en-GB,en-US;q=0.7,zh-CN;q=0.3\r\n"                           // en-GB,en-US;q=0.7,zh-CN;q=0.3\r\n" 
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -
        0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,                 // Language
        0x3a,                                                           // :
        0x20,                                                           // ( space )                    
        0x65, 0x6e, 0x2d, 0x47, 0x42,                                   // "en-GB"
        0x2c,                                                           // ','
        0x65, 0x6e, 0x2d, 0x55, 0x53,                                   // "en-US"
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37,                             // ";q=0.7"
        0x2c,                                                           // ','
        0x7a, 0x68, 0x2d, 0x43, 0x4e,                                   // "zh-CN"
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x33,                             // ";q=0.3"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Accept-Encoding: gzip, deflate\r\n"                 // Header: "Accept-Encoding: gzip, deflate\r\n"     
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -               
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,                 // Encoding             
        0x3a,                                                           // :
        0x20,                                                           // ( space )                     
        0x67, 0x7a, 0x69, 0x70,                                         // "gzip"
        0x2c, 0x20,                                                     // ", "
        0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65,                       // "deflate"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Connection: keep-alive\r\n"                         // Header: "Connection: keep-alive\r\n"   
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,     // Connection
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65,     // "keep-alive"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Upgrade-Insecure-Requests: 1\r\n"                   // Header: "Upgrade-Insecure-Requests: 1\r\n"   
        0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65,                       // Upgrade            
        0x2d,                                                           // -
        0x49, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,                 // Insecure
        0x2d,                                                           // -
        0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73,                 // Requests
        0x3a,                                                           // : 
        0x20,                                                           // ( space ) 
        0x31,                                                           // 1
        0x0d, 0x0a,                                                     // \r\n                                                                 
        0x0d, 0x0a                                                      // \r\n                                     
    };                                                                  

    inline const unsigned char tcp_ack_get_packet[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination mac address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header length = 5 * 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x00, 0x34,                                                     // total length of packet
        0x80, 0x9c,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x06,                                                           // TCP protocol
        0x38, 0xae,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip address
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip address
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port
        0xac, 0x18,                                                     // destination port
        0xd3, 0xc1, 0xea, 0x0a,                                         // sequence number
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number      
        0x80,                                                           // data offset and reserved
        0x10,                                                           // flags ( ACK )
        0x01, 0xfb,                                                     // window size
        0x81, 0xa0,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x6f, 0x02, 0x0d, 0x72, 0x9a      // timestamp
    };    

    inline const unsigned char http_response_packet[] = {
        /* rthernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* IPv4 header */
        0x45,                                                           // version = 4, header length = 5 * 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x01, 0x03,                                                     // total length of packet
        0x80, 0x9d,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x06,                                                           // tcp protocol
        0x37, 0xde,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source IP address
        0xc0, 0xa8, 0x00, 0x14,                                         // destination IP address
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port
        0xac, 0x18,                                                     // destination port
        0xd3, 0xc1, 0xea, 0x0a,                                         // sequence number
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number
        0x80,                                                           // data offset and reserved
        0x18,                                                           // flags ( ACK ) 
        0x01, 0xfb,                                                     // window size
        0x82, 0x6f,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01, 0x01,                                                     // NOP
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x70, 0x02, 0x0d, 0x72, 0x9a,     // timestamp 
        /* http response */                                             /* http response */
        /* http version and status code */                              /* http version and status code */
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x2f,                                                           // / 
        0x31, 0x2e, 0x31,                                               // 1.1
        0x20,                                                           // ( space )
        0x32, 0x30, 0x30,                                               // 200
        0x20,                                                           // ( space )
        0x4f, 0x4b,                                                     // OK
        0x0d, 0x0a,                                                     // \n
        /* headers */                                                   /* headers */
        /* Content-Type: text/plain */                                  /* Content-Type: text/plain */
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content
        0x2d,                                                           // -
        0x54, 0x79, 0x70, 0x65,                                         // Type
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x74, 0x65, 0x78,0x74,                                          // text                                                           
        0x2f,                                                           // /
        0x70, 0x6c, 0x61, 0x69, 0x6e, // text/                          // plain                     
        0x0d, 0x0a,                                                     // \n
        /* Date: Tue, 13 May 2025 08:07:35 GMT */                       /* Date: Tue, 13 May 2025 08:07:35 GMT */
        0x44, 0x61, 0x74, 0x65,                                         // Date                               
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x54, 0x75, 0x65,                                               // Tue 
        0x2c,                                                           // ,
        0x20,                                                           // ( space )
        0x31, 0x33,                                                     // 13
        0x20,                                                           // ( space )
        0x4d, 0x61, 0x79,                                               // May
        0x20,                                                           // ( space )
        0x32, 0x30, 0x32, 0x35,                                         // 2025
        0x20,                                                           // ( space )
        0x30, 0x38, 0x3a, 0x30, 0x37, 0x3a, 0x33, 0x35,                 // 08:07::35
        0x20,                                                           // ( space )
        0x47, 0x4d, 0x54,                                               // GMT 
        0x0d, 0x0a,                                                     // \n
        /* Connection: keep-alive */                                    /* Connection: keep-alive */
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,     // Connection
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x6b, 0x65, 0x65, 0x70,                                         // keep
        0x2d,                                                           // -
        0x61, 0x6c, 0x69, 0x76, 0x65,                                   // alive
        0x0d, 0x0a,                                                     // \n
        /* Keep-Alive: timeout=5 */                                     /* Keep-Alive: timeout=5 */
        0x4b, 0x65, 0x65, 0x70,                                         // Keep
        0x2d,                                                           // -
        0x41, 0x6c, 0x69, 0x76, 0x65,                                   // Alive
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x74, 0x69, 0x6d, 0x65,                                         // time
        0x6f, 0x75, 0x74,                                               // out
        0x3d,                                                           // =
        0x35,                                                           // 5
        0x0d, 0x0a,                                                     // \n 
        /* Transfer-Encoding: chunked */                                /* Transfer-Encoding: chunked */
        0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72,                 // Transfer
        0x2d,                                                           // -
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,                 // Encoding
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x63, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64,                       // chunked
        /* end of headers */                                            /* end of headers */
        0x0d, 0x0a,                                                     // \n
        0x0d, 0x0a,                                                     // \n
        /* http body */                                                 /* http body */
        // "27\nHello, World from Node.js HTTP server!\n"               // "27\nHello, World from Node.js HTTP server!\n"
        0x32, 0x37,                                                     
        0x0d, 0x0a,                                                     // \n 
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,                             // Hello,
        0x20,                                                           // ( space )
        0x57, 0x6f, 0x72, 0x6c, 0x64,                                   // World
        0x20,                                                           // ( space ) 
        0x66, 0x72, 0x6f, 0x6d,                                         // from
        0x20,                                                           // ( space )
        0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x6a, 0x73,                       // Node.js
        0x20,                                                           // ( space )
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x20,                                                           // ( space )
        0x73, 0x65, 0x72, 0x76, 0x65, 0x72,                             // server 
        0x21,                                                           
        0x0a, 0x0d,                                                     
        0x0a, 0x30,                                                     
        0x0d, 0x0a,                                                     
        0x0d, 0x0a                                                      // \n
    };                                                                  

    inline const unsigned char tcp_ack_response_packet[] = {            
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination MAC address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source MAC address
        0x08, 0x00,                                                     // ether-type ( ipv4 )
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header-length = 5 (20 bytes)
        0x00,                                                           // type of service ( ToS )
        0x00, 0x34,                                                     // total length
        0x44, 0xee,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL ( time-to-live )
        0x06,                                                           // protocol ( TCP )
        0x74, 0x5c,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip address
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip address
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // source port
        0x0b, 0xb8,                                                     // destination port
        0xb9, 0x20, 0xcb, 0x16,                                         // sequence number
        0xd3, 0xc1, 0xea, 0xd9,                                         // acknowledgment number
        0x80,                                                           // data offset + reserved
        0x10,                                                           // flags ( ACK )
        0x00, 0x83,                                                     // window size
        0x70, 0x9d,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP 
        0x01,                                                           // NOP 
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x9d, 0x58, 0x64, 0xbc, 0x70      // timestamp
    };                                                                  

    inline const unsigned char tcp_ack_of_ack_packet[] = {              
        /* ethernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination MAC address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source MAC address
        0x08, 0x00,                                                     // ether-type ( 0x0800 = ipv4 )
        /* IPv4 Header */                                               /* ipv4 header */
        0x45,                                                           // version ( 4 ) and header-length ( 20 bytes )
        0x00,                                                           // type of service ( 0 )
        0x00, 0x34,                                                     // total-length ( 0x0034 = 52 bytes )
        0x80, 0x9e,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset ( 0x4000, no fragmentation )
        0x40,                                                           // time-to-Live ( TTL ) = 64
        0x06,                                                           // protocol ( 0x06 = TCP )
        0x74, 0x5c,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip address ( 192.168.0.21 )
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip address ( 192.168.0.20 )
        /* TCP Header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port ( 0x0bb8 = 3032 )
        0xac, 0x18,                                                     // destination port ( 0xac18 = 44248 )
        0xd3, 0xc1, 0xea, 0xd9,                                         // sequence number ( 0xd3c1ead9 )
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number 
        0x80,                                                           // data offset & reserved 
        0x11,                                                           // flags ( 0x11 = ACK, push flag set )
        0x01, 0xfb,                                                     // window size (0x01fb = 511)
        0x81, 0xa0,                                                     // checksum 
        0x00, 0x00,                                                     // urgent pointer 
        /* TCP Options */                                               /* tcp options */
        0x01,                                                           // NOP 
        0x01,                                                           // NOP
        0x08, 0x0a, 0x58, 0x64, 0xcf, 0xfc, 0x02, 0x0d, 0x72, 0x9d      // timestamp
    };                                                                  


    inline const unsigned char ethernet_frame_udp[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x04, 0x81, 0x9b, 0x17, 0x26, 0x81,                             // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header-length = 5 X 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x00, 0x3f,                                                     // total length of packet
        0xdd, 0x2e,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x11,                                                           // protocol
        0x00, 0x00,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source IP address
        0xad, 0xc2, 0x03, 0x49,                                         // destination IP address
        /* udp header */                                                /* udp header */
        0x01, 0xbb,                                                     // source port
        0xce, 0xb9,                                                     // destination port
        0x04, 0xea,                                                     // length
        0x01, 0xb8                                                      // checksum
    };                                                                  

    inline const unsigned char ethernet_frame_tcp[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination mac address
        0x04, 0x81, 0x9b, 0x17, 0x26, 0x81,                             // source mac address
        0x08, 0x00,                                                     // ether-type 
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           
        0x00,                                                           
        0x01, 0xf9,                                                      
        0x34, 0x64,                                                     
        0x40, 0x00,                                                     
        0x70,                                                           
        0x06,                                                           // protocol 
        0xbe, 0x5e,                                                     
        0x14, 0x2a, 0x41, 0x55,                                         
        0xc0, 0xa8, 0x00, 0x15,                                         
        /* tcp header */                                                /* tcp header */ 
        0x01, 0xbb,                                                     // source port
        0xcd, 0xcc,                                                     // destination port
        0x9f, 0xa5, 0x08, 0x57,                                         // sequence number
        0x1d, 0x42, 0x03, 0xb7,                                         // acknowledgment number
        0x50, 0x19,                                                     // data offset
        0x40, 0x02,                                                     // window size
        0x95, 0x2f,                                                     // checksum
        0x00, 0x00                                                      // urgent pointer
    };

} // test

#endif