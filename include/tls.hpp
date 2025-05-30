#ifndef TLS_HPP
#define TLS_HPP

#include <array>
#include <map>
#include <vector>
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

namespace ntk {

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

    std::string client_random_to_hex( const std::array<uint8_t,32>& random );

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len );

    std::vector<tls_record> decrypt_tls_data(
        const std::array<uint8_t,32>& client_random,
        const std::array<uint8_t,32>& server_random,
        const uint16_t tls_version,
        const uint16_t cipher_suite,
        const std::vector<tls_record>& encrypted_records,
        const secrets& session_keys );

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num );

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label );

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, uint16_t version, uint16_t length );

} // namespace ntk

#endif