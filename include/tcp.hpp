#ifndef TCP_HPP
#define TCP_HPP

#include <cstdint>
#include <cstring>

#include <algorithm>
#include <vector>
#include <map>
#include <unordered_set>
#include <variant>
#include <span>
#include <iostream>
#include <limits>
#include <expected>

#include <ipv4.hpp>
#include <constants.hpp>
#include <spmc_queue.hpp>

namespace ntk {

    enum class tcp_flags : uint8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        ACK = 0x10,
        FIN_ACK = 0x11,
        SYN_ACK = 0x12
    };

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

        bool operator==( const tcp_handshake& other ) const {
            return syn == other.syn && syn_ack == other.syn_ack && ack == other.ack;
        }

        bool empty() const {
            return syn.empty() && syn_ack.empty() && ack.empty();
        }
    };

    using fin_ack_fin_ack = std::array<std::vector<uint8_t>,4>;
    using rst = std::vector<uint8_t>;

    struct tcp_termination {
        std::variant<fin_ack_fin_ack,rst> closing_sequence;  

        bool operator==( const tcp_termination& other ) const {
            return closing_sequence == other.closing_sequence;
        }
    };

    std::vector<uint8_t> extract_tcp_header( const unsigned char* ethernet_frame, const size_t ipv4_header_len );

    tcp_header parse_tcp_header( const std::vector<uint8_t>& raw_tcp_header );

    tcp_header get_tcp_header( const unsigned char* ethernet_frame );

    tcp_header get_tcp_header( const std::vector<uint8_t>& packet );

    bool is_non_overlapping_stream( const tcp_stream& stream );

    std::vector<raw_tcp_frame> extract_raw_tcp_stream( const session& tcp_session );

    raw_tcp_stream extract_tcp_stream( const session& tcp_session );

    tcp_stream parse_tcp_stream( const raw_tcp_stream& raw_stream );

    tcp_stream get_tcp_stream( const std::vector<raw_tcp_frame>& raw_stream );

    tcp_stream merge_tcp_stream_non_overlapping( const tcp_stream& stream );

    tcp_stream get_merged_tcp_stream( const session& packet_data ); 

    std::vector<uint8_t> extract_payload_from_ethernet( const unsigned char* ethernet_frame );

    std::vector<uint8_t> extract_payload_from_ethernet( const std::vector<uint8_t> ethernet_frame );

    bool is_tcp( const unsigned char* packet );

    bool is_tcp_v( const std::vector<uint8_t>& packet );

    tcp_handshake get_handshake( const four_tuple& four, const session& packets );

    std::vector<tcp_handshake> get_handshakes( const four_tuple& four, const session& packets );

    class tcp_transfer {
        public:
            tcp_transfer( const four_tuple& four );
            void load( const session& packet_data );
        private:
            void split_stream( const session& packet_data );
        private:
            tcp_handshake m_handshake;
            tcp_termination m_termination;
            std::vector<std::vector<uint8_t>> m_client_acks;
            std::vector<std::vector<uint8_t>> m_server_acks;
            std::vector<std::vector<uint8_t>> m_client_traffic;
            std::vector<std::vector<uint8_t>> m_server_traffic;
            
            four_tuple m_four;

            friend class tcp_transfer_friend_helper;
    };

    struct tcp_handshake_feed { 

        bool feed( const std::vector<uint8_t>& packet );
    private:
        bool feed_packet( const std::vector<uint8_t>& packet ); 
    public:
        void reset() {
            m_syn = m_syn_ack = m_ack = std::nullopt;
        }

        tcp_handshake_feed( const four_tuple& four ) 
            : m_four( four ), m_complete( false ) {}

        four_tuple m_four;
        tcp_handshake m_handshake;

        bool m_complete;
        std::optional<std::vector<uint8_t>> m_syn;
        std::optional<std::vector<uint8_t>> m_syn_ack;
        std::optional<std::vector<uint8_t>> m_ack;
    };

    struct tcp_termination_feed { 
    
        bool feed( const std::vector<uint8_t>& packet );
    private:
        bool feed_packet( const std::vector<uint8_t>& packet );
    public:
        tcp_termination_feed( const four_tuple& four ) 
            : m_four( four ), m_fin_1_seq_number( std::numeric_limits<uint32_t>::max() ),
              m_fin_2_seq_number( std::numeric_limits<uint32_t>::max() ), m_complete( false ) {}

        four_tuple m_four;
        bool m_complete;

        tcp_termination m_termination;

        std::optional<std::vector<uint8_t>> m_fin_1;
        std::optional<std::vector<uint8_t>> m_ack_1;
        std::optional<std::vector<uint8_t>> m_fin_2;
        std::optional<std::vector<uint8_t>> m_ack_2;

        uint32_t m_fin_1_seq_number;
        uint32_t m_fin_2_seq_number;
    };

    class tcp_live_stream {
        public:
            tcp_live_stream( const four_tuple& four );

            tcp_live_stream( const tcp_live_stream& ) = default;
            tcp_live_stream( tcp_live_stream&& ) = default;
            tcp_live_stream& operator=(tcp_live_stream&& ) = default;

            bool operator==( const tcp_live_stream& other ) const;

            bool is_complete() const;
            bool feed( const std::vector<uint8_t>& packet );
            const four_tuple& get_four_tuple() const;

            template<typename Predicate>
            bool traffic_contains( Predicate predicate ) const {
                return std::any_of( m_traffic.begin(), m_traffic.end(), predicate );
            }
        private:
            tcp_handshake_feed m_handshake_feed;
            tcp_termination_feed m_termination_feed;
        protected:
            std::vector<std::vector<uint8_t>> m_traffic;
        private:
            four_tuple m_four;

            friend class tcp_live_stream_friend_helper;

            friend std::ostream& operator<<( std::ostream& os, const tcp_live_stream& live_stream );
            friend void output_stream_to_file( const std::string& filename, const tcp_live_stream& live_stream );
    };

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

    std::vector<tcp_termination> get_terminations( const four_tuple& four, const session& packets );

    class tcp_transfer_friend_helper {
        public:
            static const tcp_handshake& handshake( const tcp_transfer& t );
            static const tcp_termination& termination( const tcp_transfer& t );
            static const std::vector<std::vector<uint8_t>>& client_acks( const tcp_transfer& t );
            static const std::vector<std::vector<uint8_t>>& server_acks( const tcp_transfer& t );
            static const std::vector<std::vector<uint8_t>>& client_traffic( const tcp_transfer& t );
            static const std::vector<std::vector<uint8_t>>& server_traffic( const tcp_transfer& t );
            static const four_tuple& four( const tcp_transfer& t );
    };

    class tcp_live_stream_friend_helper {
        public:
            static const tcp_handshake_feed& handshake_feed( const tcp_live_stream& t );
            static const tcp_termination_feed& termination_feed( const tcp_live_stream& t );
            static const std::vector<std::vector<uint8_t>>& traffic( const tcp_live_stream& t );
            static const four_tuple& four( const tcp_live_stream& t );
    };

    const std::vector<uint8_t>* get_end_of_handshake( const session& packets, 
                                                      const four_tuple& four,
                                                      const tcp_handshake& handshake );

    const std::vector<uint8_t>* get_start_of_termination( const session& packets, 
                                                          const four_tuple& four,
                                                          const tcp_termination& termination );

    bool is_data_packet( const std::vector<uint8_t>& packet );

    bool is_ack_only_packet( const std::vector<uint8_t>& packet );

    bool is_reset( const std::vector<uint8_t>& packet );

    bool is_syn( const std::vector<uint8_t>& packet );

    class tcp_live_stream_session { 

        public:
            tcp_live_stream_session();
            tcp_live_stream_session( transfer_queue_interface<tcp_live_stream>* offload_queue );
            void feed( const std::vector<uint8_t>& packet );
            size_t number_of_completed_transfers();
        private:
            void offload( tcp_live_stream&& stream );

            std::vector<tcp_live_stream> m_live_streams;
            std::unordered_set<four_tuple> m_four_tuples;

            transfer_queue_interface<tcp_live_stream>* m_offload_queue;

            friend class tcp_live_stream_session_friend_helper;
    }; 

    class tcp_live_stream_session_friend_helper {
        public:
            static const tcp_live_stream& get_live_stream( const tcp_live_stream_session& t, const four_tuple& four );
            static const std::vector<tcp_live_stream>& live_streams( const tcp_live_stream_session& t );
            static const std::unordered_set<four_tuple>& four_tuples( const tcp_live_stream_session& t );
    };

    bool is_valid_handshake( const tcp_handshake& handshake );

    bool is_valid_fin_ack_fin_ack( const fin_ack_fin_ack& closing_sequence );

    bool is_valid_fin_ack_fin_ack( const tcp_termination& termination );

    struct four_tuple_filter {
        bool operator()( const ntk::tcp_live_stream& stream ) {
            return m_four == stream.get_four_tuple();
        }
        four_tuple_filter( const ntk::four_tuple& four ) 
            : m_four( four ) {}

        four_tuple m_four;
    };

    std::vector<std::vector<uint8_t>> extract_payloads( const four_tuple& four, const std::vector<std::vector<uint8_t>>& packets );

    std::expected<std::vector<std::vector<uint8_t>>,std::string> extract_client_packets( const session& packets );

    std::expected<std::vector<std::vector<uint8_t>>,std::string> extract_server_packets( const session& packets ); 

    struct client_server_payloads {
        std::vector<std::vector<uint8_t>> client_payloads;
        std::vector<std::vector<uint8_t>> server_payloads;
    };

    std::expected<client_server_payloads,std::string> split_payloads( const session& packets );

} // namespace ntk

#endif