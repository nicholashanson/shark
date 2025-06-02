#ifndef TLS_HPP
#define TLS_HPP

#include <array>
#include <map>
#include <vector>
#include <ranges>
#include <span>
#include <string>
#include <expected>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <tcp.hpp>

namespace ntk {

    using sni_to_ip = std::map<std::string,uint32_t>;

    const std::array<std::string,5> tls_secret_labels = {
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",  
        "EXPORTER_SECRET",
        "SERVER_TRAFFIC_SECRET_0",  
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",  
        "CLIENT_TRAFFIC_SECRET_0"
    };

    enum class tls_content_type : uint8_t {
        CHANGE_CIPHER_SEC = 0x14,
        ALERT,           // 0x15
        HANDSHAKE,       // 0x16
        APPLICATION_DATA // 0x17
    };

    enum class cipher_suite : uint16_t {
        TLS_AES_256_GCM_SHA384 = 0x1302
    };

    struct tls_record {
        tls_content_type content_type;
        uint16_t version;
        std::vector<uint8_t> payload;
    };

    struct client_hello {
        uint16_t client_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        std::vector<uint8_t> cipher_suites;
        std::vector<uint8_t> compression_methods;
        std::vector<uint8_t> extensions;
    };

    struct server_hello {
        uint16_t server_version;
        std::array<uint8_t,32> random;
        std::vector<uint8_t> session_id;
        uint16_t cipher_suite;
        uint8_t compression_method;
        std::vector<uint8_t> extensions;
    };

    struct tls_key_material {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
    };

    client_hello parse_client_hello( const std::span<const uint8_t> client_hello_bytes );

    server_hello parse_server_hello( const std::span<const uint8_t> server_hello_bytes );

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>, 
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload );

    using secrets = std::map<std::string,std::map<std::string,std::vector<uint8_t>>>;

    secrets get_tls_secrets( const std::string& filename );

    secrets get_tls_secrets( const std::string& filename, std::array<uint8_t,32> client_random );

    std::string client_random_to_hex( const std::array<uint8_t,32>& random );

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id );

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len );

    std::vector<tls_record> decrypt_tls_data(
        const std::array<uint8_t,32>& client_random,
        const std::array<uint8_t,32>& server_random,
        const uint16_t tls_version,
        const uint16_t cipher_suite,
        const std::vector<tls_record>& encrypted_records,
        const secrets& session_keys,
        const std::string& secret_label = "SERVER_HANDSHAKE_TRAFFIC_SECRET" );

    tls_record decrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const uint16_t tls_version,
                               const uint16_t cipher_suite,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num );

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num );

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label );

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, uint16_t version, uint16_t length );

    std::vector<uint8_t> extract_certificate( const std::vector<uint8_t>& handshake_payload );

    bool is_tls( const unsigned char* packet );

    bool is_tls_v( const std::vector<uint8_t>& packet );

    bool is_client_hello( const unsigned char* packet );

    bool is_client_hello_v( const std::vector<uint8_t>& packet );

    bool is_tls_alert( const unsigned char* packet );
    
    bool is_tls_alert_v( const std::vector<uint8_t>& packet );

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs );

    bool is_complete_secrets( const std::map<std::string,std::vector<uint8_t>>& secrets );

    client_hello get_client_hello( const std::span<const uint8_t> tcp_payload );

    std::expected<std::string,std::string> get_sni( const client_hello& hello );

    std::vector<std::string> get_snis( const session& packets, const std::string& host );

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host );

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host );

    sni_to_ip get_sni_to_ip( const session& packets );

    client_hello get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame );

    client_hello get_client_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame );

    server_hello get_server_hello_from_ethernet_frame( const unsigned char* ethernet_frame );

    server_hello get_server_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame );

} // namespace ntk

#endif