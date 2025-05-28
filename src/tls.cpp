#include <tls.hpp>

namespace ntk {

    client_hello parse_client_hello( const std::span<const uint8_t> client_hello_bytes ) {

        const size_t client_version_len = 2;
        const size_t random_len = 32;
        const size_t session_id_len_pos = client_version_len + random_len;

        client_hello c_hello;

        c_hello.client_version = ( client_hello_bytes[ 0 ] << 8 ) | client_hello_bytes[ 1 ];
        std::memcpy( c_hello.random.data(), &client_hello_bytes[ client_version_len ], random_len );

        const size_t session_id_len = client_hello_bytes[ client_version_len + random_len ];
        c_hello.session_id.resize( session_id_len );
        std::memcpy( c_hello.session_id.data(), &client_hello_bytes[ client_version_len + random_len + 1 ], session_id_len );

        const size_t cipher_suites_len_pos = session_id_len_pos + session_id_len;
        const size_t cipher_suites_pos = cipher_suites_len_pos + 2;
        size_t cipher_suites_len = ( client_hello_bytes[ cipher_suites_len_pos ] << 8 ) | client_hello_bytes[ cipher_suites_len_pos + 1 ];
        c_hello.cipher_suites.resize( cipher_suites_len );
        std::memcpy( c_hello.cipher_suites.data(), &client_hello_bytes[ cipher_suites_pos ], cipher_suites_len );
        
        const size_t compression_methods_len_pos = cipher_suites_pos + cipher_suites_len;
        const size_t compression_methods_len = client_hello_bytes[ cipher_suites_pos ];
        c_hello.compression_methods.resize( compression_methods_len );
        std::memcpy( c_hello.compression_methods.data(), &client_hello_bytes[ compression_methods_len_pos + 1 ], compression_methods_len );

        const size_t extensions_len_pos = compression_methods_len_pos + 1 + compression_methods_len;
        const size_t extensions_len = ( client_hello_bytes[ extensions_len_pos ] << 8) | client_hello_bytes[ extensions_len_pos + 1 ];
        c_hello.extensions.resize( extensions_len );
        std::memcpy( c_hello.extensions.data(), &client_hello_bytes[ extensions_len_pos + 2 ], extensions_len );

        return c_hello;
    }

    server_hello parse_server_hello( const std::span<const uint8_t> server_hello_bytes ) {

        const size_t version_len = 2;
        const size_t random_len = 32;
        const size_t session_id_len_pos = version_len + random_len;

        server_hello s_hello;

        s_hello.server_version = ( server_hello_bytes[ 0 ] << 8 ) | server_hello_bytes[ 1 ];

        std::memcpy( s_hello.random.data(), &server_hello_bytes[version_len], random_len );

        const size_t session_id_len = server_hello_bytes[ session_id_len_pos ];
        s_hello.session_id.resize( session_id_len );
        std::memcpy( s_hello.session_id.data(), &server_hello_bytes[ session_id_len_pos + 1 ], session_id_len );

        const size_t cipher_suite_pos = session_id_len_pos + 1 + session_id_len;
        s_hello.cipher_suite = ( server_hello_bytes[cipher_suite_pos] << 8 ) | server_hello_bytes[ cipher_suite_pos + 1 ];

        const size_t compression_method_pos = cipher_suite_pos + 2;
        s_hello.compression_method = server_hello_bytes[ compression_method_pos ];

        const size_t extensions_len_pos = compression_method_pos + 1;
        const size_t extensions_len = ( server_hello_bytes[ extensions_len_pos ] << 8 ) | server_hello_bytes[ extensions_len_pos + 1 ];
        s_hello.extensions.resize( extensions_len );
        std::memcpy( s_hello.extensions.data(), &server_hello_bytes[ extensions_len_pos + 2 ], extensions_len );

        return s_hello;
    }

    std::expected<
        std::tuple<std::vector<tls_record>,size_t>,
        std::string
    > split_tls_records( std::span<const uint8_t> tls_payload ) {

        size_t offset_reached = 0;

        if ( tls_payload.size() == 0 ) return std::unexpected( "TLS payload is empty" );

        std::vector<tls_record> records;

        while ( !tls_payload.empty() ) {

            const uint8_t& first_byte = tls_payload[ 0 ];

            tls_record rec;
            rec.content_type = static_cast<tls_content_type>( first_byte );

            uint16_t version = ( tls_payload[ 1 ] << 8 ) | tls_payload[ 2 ];
            uint16_t record_len = ( tls_payload[ 3 ] << 8 ) | tls_payload[ 4 ];
            
            rec.version = version;

            if ( 5 + record_len <= tls_payload.size() ) {
                rec.payload.assign( tls_payload.begin() + 5, tls_payload.begin() + 5 + record_len );
                records.push_back( rec );
                offset_reached += 5 + record_len;
            } else {
                break;
            }

            tls_payload = tls_payload.subspan( 5 + record_len );
        }

        return std::make_tuple( records, offset_reached );
    }

} // namespace ntk