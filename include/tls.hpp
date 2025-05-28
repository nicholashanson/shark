#ifndef TLS_HPP
#define TLS_HPP

#include <array>
#include <vector>
#include <span>
#include <string>
#include <expected>

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace ntk {

    enum class tls_content_type : uint8_t {
        CHANGE_CIPHER_SEC = 0x14,
        ALERT,           // 0x15
        HANDSHAKE,       // 0x16
        APPLICATION_DATA // 0x17
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

    client_hello parse_client_hello( const std::span<const uint8_t> client_hello_bytes );

    server_hello parse_server_hello( const std::span<const uint8_t> server_hello_bytes );

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>, 
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload );

} // namespace ntk

#endif