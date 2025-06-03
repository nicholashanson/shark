#ifndef TCP_HPP
#define TCP_HPP

#include <cstdint>
#include <cstring>

#include <vector>
#include <map>
#include <unordered_set>
#include <variant>

#include <ipv4.hpp>
#include <constants.hpp>

namespace ntk {

    struct raw_tcp_frame {
        std::vector<uint8_t> header;
        std::vector<uint8_t> body;
    };

    using raw_tcp_stream = std::vector<std::vector<uint8_t>>;

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
        uint8_t flags;
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

    struct four_tuple { 
        uint32_t client_ip;
        uint32_t server_ip;
        uint16_t client_port;
        uint16_t server_port;

        bool operator==( const four_tuple& other ) const {
            return client_ip == other.client_ip &&
                server_ip == other.server_ip &&
                client_port == other.client_port &&
                server_port == other.server_port;
        }
    };

    struct tcp_handshake {
        std::vector<uint8_t> syn;
        std::vector<uint8_t> syn_ack;
        std::vector<uint8_t> ack;
    };

    using fin_ack_fin_ack = std::array<std::vector<uint8_t>,4>;
    using rst = std::vector<uint8_t>;

    struct tcp_termination {
        std::variant<fin_ack_fin_ack,rst> closing_sequence;  
    };

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    tcp_header parse_tcp_header( const std::vector<uint8_t>& raw_tcp_header );

    tcp_header get_tcp_header( const unsigned char* ethernet_frame );

    bool is_non_overlapping_stream( const tcp_stream& stream );

    std::vector<raw_tcp_frame> extract_raw_tcp_stream( const session& tcp_session );

    raw_tcp_stream extract_tcp_stream( const session& tcp_session );

    tcp_stream parse_tcp_stream( const raw_tcp_stream& raw_stream );

    tcp_stream get_tcp_stream( const std::vector<raw_tcp_frame>& raw_stream );

    tcp_stream merge_tcp_stream_non_overlapping( const tcp_stream& stream );

    tcp_stream get_merged_tcp_stream( const session& packet_data ); 

    std::vector<uint8_t> extract_payload_from_ethernet( const unsigned char* ethernet_frame );

    bool is_tcp( const unsigned char* packet );

    bool is_tcp_v( const std::vector<uint8_t>& packet );

    tcp_handshake get_handshake( const four_tuple& four, const session& packets );

    std::vector<tcp_handshake> get_handshakes( const four_tuple& four, const session& packets );

    class tcp_transfer;

    four_tuple get_four_from_ethernet( const unsigned char* packet );

    four_tuple get_four_from_ethernet( const std::vector<uint8_t>& packet );

    four_tuple flip_four( const four_tuple& four );

} // namespace ntk

namespace std {

    template <>
    struct hash<ntk::four_tuple> {
        size_t operator()( const ntk::four_tuple& ft ) const noexcept {
            size_t h1 = hash<uint32_t>{}( ft.client_ip );
            size_t h2 = hash<uint32_t>{}( ft.server_ip );
            size_t h3 = hash<uint16_t>{}( ft.client_port );
            size_t h4 = hash<uint16_t>{}( ft.server_port );
            return h1 ^ ( h2 << 1 ) ^ ( h3 << 2 ) ^ ( h4 << 3 ); 
        }
    };

} // namespace std

namespace ntk {

    std::unordered_set<four_tuple> get_four_tuples( const session& packets );

    tcp_termination get_termination( const four_tuple& four, const session& packets );

} // namespace ntk

#endif