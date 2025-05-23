#ifndef TCP_HPP
#define TCP_HPP

#include <cstdint>
#include <cstring>

#include <vector>
#include <map>

#include <ipv4.hpp>
#include <http.hpp>
#include <utils.hpp>

namespace shark {

    struct raw_tcp_frame {
        std::vector<uint8_t> header;
        std::vector<uint8_t> body;
    };

    using raw_tcp_stream = std::vector<std::vector<uint8_t>>;

    using tcp_stream = std::map<uint32_t,std::vector<uint8_t>>; 

    struct tcp_option {
        uint8_t type;
        std::vector<uint8_t> option;

        bool operator==( const tcp_option& other ) const {
            return type == other.type && option == other.option;
        }        
    };

    struct tcp_header {
        uint16_t source_port;
        uint16_t destination_port;
        uint32_t sequence_number;
        uint32_t acknowledgment_number;
        uint16_t data_offset;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_pointer;

        std::vector<tcp_option> options;

        bool operator==( const tcp_header& other ) const {
            return source_port == other.source_port &&
                destination_port == other.destination_port &&
                sequence_number == other.sequence_number &&
                acknowledgment_number == other.acknowledgment_number &&
                data_offset == other.data_offset &&
                window_size == other.window_size &&
                checksum == other.checksum &&
                urgent_pointer == other.urgent_pointer &&
                options == other.options;
        }
    };

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    tcp_header parse_tcp_header( const std::vector<uint8_t>& raw_tcp_header );

    bool is_non_overlapping_stream( const tcp_stream& stream );

    std::vector<raw_tcp_frame> extract_raw_tcp_stream( const session& tcp_session );

    raw_tcp_stream extract_tcp_stream( const session& tcp_session );

    tcp_stream parse_tcp_stream( const raw_tcp_stream& raw_stream );

    tcp_stream get_tcp_stream( const std::vector<raw_tcp_frame>& raw_stream );

    tcp_stream merge_tcp_stream_non_overlapping( const tcp_stream& stream );

} // namespace shark

#endif