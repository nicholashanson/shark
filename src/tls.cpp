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

        const size_t cipher_suites_len_pos = session_id_len_pos + 1 + session_id_len;
        const size_t cipher_suites_pos = cipher_suites_len_pos + 2;
        size_t cipher_suites_len = ( client_hello_bytes[ cipher_suites_len_pos ] << 8 ) | client_hello_bytes[ cipher_suites_len_pos + 1 ];
        c_hello.cipher_suites.resize( cipher_suites_len );
        std::memcpy( c_hello.cipher_suites.data(), &client_hello_bytes[ cipher_suites_pos ], cipher_suites_len );
        
        const size_t compression_methods_len_pos = cipher_suites_pos + cipher_suites_len;
        const size_t compression_methods_len = client_hello_bytes[ compression_methods_len_pos ];
        c_hello.compression_methods.resize( compression_methods_len );
        std::memcpy( c_hello.compression_methods.data(), &client_hello_bytes[ compression_methods_len_pos + 1 ], compression_methods_len );

        const size_t extensions_len_pos = compression_methods_len_pos + 1 + compression_methods_len;
        const size_t extensions_len = ( client_hello_bytes[ extensions_len_pos ] << 8) | client_hello_bytes[ extensions_len_pos + 1 ];
        c_hello.extensions.resize( extensions_len );
        std::memcpy( c_hello.extensions.data(), &client_hello_bytes[ extensions_len_pos + 2 ], extensions_len );

        return c_hello;
    }

    client_hello get_client_hello( const std::span<const uint8_t> tcp_payload ) {
        
        auto client_hello_bytes = tcp_payload.subspan( 9 );
        return parse_client_hello( client_hello_bytes );
    }

    client_hello get_client_hello( const std::vector<uint8_t>& tcp_payload ) {
        
        auto tls_record_span = std::span<const uint8_t>( tcp_payload );
        auto client_hello_bytes = tls_record_span.subspan( 9 );
        return parse_client_hello( client_hello_bytes );
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

    server_hello get_server_hello( const std::span<const uint8_t> tcp_payload ) {
        
        auto server_hello_bytes = tcp_payload.subspan( 9 );
        return parse_server_hello( server_hello_bytes );
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

    secrets get_tls_secrets( const std::string& filename ) {

        secrets tls_secrets;

        std::ifstream file( filename );
        std::string line;

        while ( std::getline( file, line ) ) {

            if ( line[ 0 ] == '#' ) continue;

            std::istringstream iss( line );
            std::string label;
            std::string client_random_hex;
            std::string secret_hex;
            iss >> label >> client_random_hex >> secret_hex;

            secret_hex.erase( std::remove_if(secret_hex.begin(), secret_hex.end(),
                []( unsigned char c ) {
                    return !std::isxdigit( c );
                }), secret_hex.end() );

            std::vector<uint8_t> secret;

            for ( size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            tls_secrets[ client_random_hex ][ label ] = secret;
        }

        return tls_secrets;
    }

    secrets get_tls_secrets( const std::string& filename, std::array<uint8_t,32> client_random ) {

        auto client_random_h = client_random_to_hex( client_random );

        secrets tls_secrets;

        std::ifstream file( filename );
        std::string line;

        while ( std::getline( file, line ) ) {

            if ( line[ 0 ] == '#' ) continue;

            std::istringstream iss( line );
            std::string label;
            std::string client_random_hex;
            std::string secret_hex;
            iss >> label >> client_random_hex >> secret_hex;

            secret_hex.erase( std::remove_if(secret_hex.begin(), secret_hex.end(),
                []( unsigned char c ) {
                    return !std::isxdigit( c );
                }), secret_hex.end() );

            std::vector<uint8_t> secret;

            for ( size_t i = 0; i < secret_hex.size(); i += 2 ) {
                secret.push_back( std::stoi( secret_hex.substr( i, 2 ), nullptr, 16 ) );
            }

            if ( client_random_hex == client_random_h ) 
                tls_secrets[ client_random_hex ][ label ] = secret;

            if ( is_complete_secrets( tls_secrets[ client_random_hex ] ) )
                break;
        }

        return tls_secrets;
    }

    bool is_complete_secrets( const std::map<std::string,std::vector<uint8_t>>& secrets ) {

        if ( secrets.size() != 5 ) return false;
        std::array<std::string,5> labels;
        size_t count = 0;

        for ( auto [ label, secret ] : secrets ) {
            labels[ count ] = label;
            count += 1;
        }
        return secret_labels_are_equal( labels, tls_secret_labels );
    }

    std::string client_random_to_hex( const std::array<uint8_t,32>& random ) {
        std::ostringstream oss;
        for ( auto byte : random )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    std::string session_id_to_hex( const std::vector<uint8_t>& session_id ) {
        std::ostringstream oss;
        for ( auto byte : session_id )
            oss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << int( byte );
        return oss.str();
    }

    std::vector<uint8_t> get_traffic_secret( const secrets& session_keys,
                                             const std::array<uint8_t,32>& client_random,
                                             const std::string& label ) {

        auto client_hex = client_random_to_hex( client_random );
        return session_keys.at( client_hex ).at( label );
    }

    std::vector<uint8_t> build_tls13_nonce( const std::vector<uint8_t>& base_iv, uint64_t seq_num ) {
        std::vector<uint8_t> nonce = base_iv;
        for ( int i = 0; i < 8; ++i ) {
            nonce[ nonce.size() - 8 + i ] ^= static_cast<uint8_t>( ( seq_num >> ( 56 - 8 * i ) ) & 0xff );
        }
        return nonce;
    }

    std::vector<uint8_t> hkdf_expand_label( const std::vector<uint8_t>& secret, const std::string& label,              
                                            const std::vector<uint8_t>& context, size_t out_len, const EVP_MD* hash_func ) {
    
        std::string full_label = "tls13 " + label;

        std::vector<uint8_t> hkdf_label;

        hkdf_label.push_back( static_cast<uint8_t>( ( out_len >> 8 ) & 0xFF ) );
        hkdf_label.push_back( static_cast<uint8_t>( out_len & 0xFF ) );

        hkdf_label.push_back( static_cast<uint8_t>( full_label.size() ) );
        hkdf_label.insert( hkdf_label.end(), full_label.begin(), full_label.end() );

        hkdf_label.push_back( static_cast<uint8_t>( context.size() ) );
        hkdf_label.insert( hkdf_label.end(), context.begin(), context.end() );

        std::vector<uint8_t> out( out_len );

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, nullptr );
        if ( !ctx ) throw std::runtime_error( "EVP_PKEY_CTX_new_id failed" );

        if ( EVP_PKEY_derive_init( ctx ) <= 0 ||
             EVP_PKEY_CTX_set_hkdf_mode( ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY ) <= 0 ||
             EVP_PKEY_CTX_set_hkdf_md( ctx, hash_func ) <= 0 ||
             EVP_PKEY_CTX_set1_hkdf_key( ctx, secret.data(), secret.size() ) <= 0 ||
             EVP_PKEY_CTX_add1_hkdf_info( ctx, hkdf_label.data(), hkdf_label.size() ) <= 0 ||
             EVP_PKEY_derive( ctx, out.data(), &out_len ) <= 0 ) {
             
            EVP_PKEY_CTX_free( ctx );
            throw std::runtime_error( "HKDF-Expand-Label failed" );
        }

        EVP_PKEY_CTX_free( ctx );
        return out;
    }

    tls_key_material derive_tls_key_iv( const std::vector<uint8_t>& secret, const EVP_MD* hash_func,
                                        size_t key_len, size_t iv_len ) {

        tls_key_material km;

        std::vector<uint8_t> context; 
        km.key = hkdf_expand_label( secret, "key", context, key_len, hash_func );
        km.iv = hkdf_expand_label( secret, "iv",  context, iv_len,  hash_func );

        return km;
    }

    std::vector<uint8_t> decrypt_aes_gcm( const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& cipher_text_with_tag ) {
        
        size_t cipher_len = cipher_text_with_tag.size() - 16;

        const uint8_t* tag = &cipher_text_with_tag[ cipher_len ];
        const uint8_t* cipher_text = &cipher_text_with_tag[ 0 ];
    
        std::vector<uint8_t> plain_text( cipher_len );

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex( ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr );
        EVP_DecryptInit_ex( ctx, nullptr, nullptr, key.data(), nonce.data() );

        int len = 0;
        EVP_DecryptUpdate( ctx, nullptr, &len, aad.data(), aad.size() );
        EVP_DecryptUpdate( ctx, plain_text.data(), &len, cipher_text, cipher_len );
        EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, 16, ( void* )tag );

        if ( EVP_DecryptFinal_ex( ctx, plain_text.data() + len, &len) <= 0 ) {
            EVP_CIPHER_CTX_free( ctx );
            throw std::runtime_error( "GCM decryption failed ( tag mismatch )" );
        }

        EVP_CIPHER_CTX_free( ctx );
        return plain_text;
    }

    std::vector<uint8_t> build_tls13_aad( tls_content_type content_type, uint16_t version, uint16_t length ) {
        return {
            static_cast<uint8_t>( content_type ),        
            static_cast<uint8_t>( version >> 8 ),      
            static_cast<uint8_t>( version & 0xff ),      
            static_cast<uint8_t>( length >> 8 ),         
            static_cast<uint8_t>( length & 0xff )        
        };
    }

    std::vector<tls_record> decrypt_tls_data( const std::array<uint8_t,32>& client_random,
                                              const std::array<uint8_t,32>& server_random,
                                              const uint16_t tls_version,
                                              const uint16_t cipher_suite,
                                              const std::vector<tls_record>& encrypted_records,
                                              const secrets& session_keys,
                                              const std::string& secret_label ) {

        auto secret = get_traffic_secret( session_keys, client_random, secret_label );

        auto key_material = derive_tls_key_iv( secret, EVP_sha384(), 32, 12 );

        std::vector<tls_record> result;
        uint64_t seq_num = 0;

        for ( const auto& record : encrypted_records ) {

            if ( record.content_type != tls_content_type::APPLICATION_DATA ) {
                result.push_back( record );
                continue;
            }

            auto nonce = build_tls13_nonce( key_material.iv, seq_num );
            auto aad = build_tls13_aad( record.content_type, record.version, record.payload.size() );
            auto decrypted_payload = decrypt_aes_gcm( key_material.key, nonce, aad, record.payload );

            result.push_back( { record.content_type, record.version, decrypted_payload } );
            seq_num++;
        }

        return result;
    }

    tls_record decrypt_record( const std::array<uint8_t,32>& client_random,
                               const std::array<uint8_t,32>& server_random,
                               const uint16_t tls_version,
                               const uint16_t cipher_suite,
                               const tls_record& record,
                               const secrets& session_keys,
                               const std::string& secret_label,
                               uint64_t seq_num ) {

        auto secret = get_traffic_secret( session_keys, client_random, secret_label );
        auto key_material = derive_tls_key_iv( secret, EVP_sha384(), 32, 12 );
        auto nonce = build_tls13_nonce( key_material.iv, seq_num );
        auto aad = build_tls13_aad( record.content_type, record.version, record.payload.size() );
        auto decrypted_payload = decrypt_aes_gcm( key_material.key, nonce, aad, record.payload );

        tls_record result { 
            record.content_type, 
            record.version, 
            decrypted_payload };

        return result;
    }

    std::vector<uint8_t> extract_certificate( const std::vector<uint8_t>& handshake_payload ) {

        size_t pos = 4; 

        uint8_t context_len = handshake_payload[ pos++ ];
        pos += context_len;

        uint32_t cert_list_len = ( handshake_payload[ pos ] << 16 ) |
                                 ( handshake_payload[ pos + 1 ] << 8 ) |
                                   handshake_payload[ pos + 2 ];
        pos += 3;

        uint32_t cert_len = ( handshake_payload[ pos ] << 16 ) |
                            ( handshake_payload[ pos + 1 ] << 8 ) |
                              handshake_payload[ pos + 2 ];
        pos += 3;

        std::vector<uint8_t> cert( handshake_payload.begin() + pos,
                                   handshake_payload.begin() + pos + cert_len );
        return cert;
    }

    bool is_tls( const unsigned char* packet ) {

        if ( !is_tcp( packet ) ) return false;
        
        auto tcp_payload = extract_payload_from_ethernet( packet );
        if ( tcp_payload.size() == 0 ) return false;

        uint8_t content_type = tcp_payload[ 0 ];
        uint8_t major_version = tcp_payload[ 1 ];

        if ( content_type < 20 || content_type > 23 ) return false; 
        if ( major_version != 3 ) return false;

        return true;
    }
    
    bool is_tls_v( const std::vector<uint8_t>& packet ) {
        return is_tls( packet.data() );
    }

    bool is_client_hello( const unsigned char* packet ) {

        if ( !is_tls( packet ) ) return false;

        auto tls_record = extract_payload_from_ethernet( packet );

        uint8_t content_type = tls_record[ 0 ];
        if ( content_type != 22 ) return false;

        uint8_t handshake_type = tls_record[ 5 ];
        return handshake_type == 1; 
    }

    bool is_client_hello_v( const std::vector<uint8_t>& packet ) {
        return is_client_hello( packet.data() );
    }

    bool is_tls_alert( const unsigned char* packet ) {
        if ( !is_tls( packet ) ) return false;

        auto tls_record = extract_payload_from_ethernet( packet );

        if ( tls_record.size() < 7 ) return false; 

        uint8_t content_type = tls_record[ 0 ];
        if ( content_type != 20 ) return false; 

        uint16_t length = ( tls_record[ 3 ] << 8 ) | tls_record[ 4 ];
        if ( length < 2 ) return false; 

        uint8_t alert_level = tls_record[ 5 ];       
        uint8_t alert_description = tls_record[ 6 ];

        if ( alert_level != 1 && alert_level != 2 ) return false;

        return true;
    }

    bool is_tls_alert_v( const std::vector<uint8_t>& packet ) {
        return is_tls_alert( packet.data() );
    }

    bool secret_labels_are_equal( std::array<std::string,5> lhs, std::array<std::string,5> rhs ) {

        std::sort( lhs.begin(), lhs.end() );
        std::sort( rhs.begin(), rhs.end() );

        return lhs == rhs;
    }

    std::expected<std::string,std::string> get_sni( const client_hello& hello ) {

        const size_t extension_length_pos = 2;
        const size_t sni_list_length_pos = 4;

        auto extension_bytes = std::span<const unsigned char>( hello.extensions );

        while ( !extension_bytes.empty() ) {

            if ( extension_bytes.size() < 4 ) {
                return std::unexpected( "Extension too short for header" );
            }

            uint16_t extension_type = ( extension_bytes[ 0 ] << 8 ) | extension_bytes[ 1 ];
            uint16_t extension_length = ( extension_bytes[ 2 ] << 8 ) | extension_bytes[ 3 ];

            if ( extension_bytes.size() < 4 + extension_length ) {
                return std::unexpected( "Extension body truncated" );
            }

            if ( extension_type == 0x0000 ) {

                if ( extension_length < 2 ) {
                    return std::unexpected( "SNI extension too short to contain list length" );
                }

                uint16_t sni_list_length = ( extension_bytes[ sni_list_length_pos ] << 8 ) | extension_bytes[ sni_list_length_pos + 1 ];

                if ( sni_list_length > extension_length - 2 ) {
                    return std::unexpected( "SNI list length exceeds bounds" );
                }

                auto sni_list = extension_bytes.subspan( sni_list_length_pos + 2 );

                while ( !sni_list.empty() ) {

                    if ( sni_list.size() < 3 ) {
                        return std::unexpected( "SNI entry too short" );
                    }

                    uint8_t name_type = sni_list[ 0 ];
                    uint16_t name_length = ( sni_list[ 1 ] << 8 ) | sni_list[ 2 ];

                    if (sni_list.size() < 3 + name_length) {
                        return std::unexpected( "Server name truncated" );
                    }

                    std::string server_name( sni_list.begin() + 3,
                                             sni_list.begin() + 3 + name_length );

                    return server_name;

                    sni_list = sni_list.subspan( 3 + name_length );
                }
            }

            extension_bytes = extension_bytes.subspan( 4 + extension_length );
        }

        return std::unexpected( "No sever name found" );
    }

    std::expected<std::string,std::string> get_sni( const std::vector<uint8_t>& hello ) {

        auto client_hello = get_client_hello_from_ethernet_frame( hello );
        auto sni = get_sni( client_hello );
        
        if ( !sni.has_value() ) {
            return std::unexpected( sni.error() );
        } else {
            return sni.value();
        }
    }

    std::expected<bool,std::string> has_sni( const client_hello& hello, const std::string& host ) {

        auto result = get_sni( hello );

        if ( !result.has_value() ) {
            return std::unexpected( result.error() );  
        }

        return result.value() == host;
    }

    std::expected<bool,std::string> sni_contains( const client_hello& hello, const std::string& host ) {

        auto result = get_sni( hello );

        if ( !result.has_value() ) {
            return std::unexpected( result.error() );  
        }

        return result.value().contains( host );
    }

    std::vector<std::string> get_snis( const session& packets, const std::string& host ) {

        std::vector<std::string> snis;

        for ( auto& client_hello_packet : packets | std::views::filter( is_client_hello_v ) ) {
            auto client_hello = get_client_hello_from_ethernet_frame( client_hello_packet );
            auto result = get_sni( client_hello );

            if ( result.has_value() ) std::cout << result.value() << std::endl;

            if ( !result.has_value() ) {
                std::cerr << result.error() << std::endl;
            }

            if ( result && result->contains( host ) ) {
                snis.push_back( *result );
            }
        }
        
        return snis;
    }

    sni_to_ip get_sni_to_ip( const session& packets ) {

        sni_to_ip results;

        for ( auto& client_hello_packet : packets | std::views::filter( is_client_hello_v ) ) {
            auto sni = get_sni( client_hello_packet );

            if ( !sni.has_value() ) {
                std::cerr << sni.error() << std::endl;
            }

            ipv4_header header = get_ipv4_header( client_hello_packet.data() );
            if ( !results.contains( sni.value() ) ) {
                results[ sni.value() ] = header.destination_ip_addr;
            }
        }

        return results;
    }

    client_hello get_client_hello_from_ethernet_frame( const unsigned char* ethernet_frame ) {
        auto tcp_payload = extract_payload_from_ethernet( ethernet_frame );
        return get_client_hello( tcp_payload );
    }

    client_hello get_client_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame ) {
        return get_client_hello_from_ethernet_frame( ethernet_frame.data() );
    }

    server_hello get_server_hello_from_ethernet_frame( const unsigned char* ethernet_frame ) {
        auto tcp_payload = std::span<const uint8_t>( extract_payload_from_ethernet( ethernet_frame ) );
        return get_server_hello( tcp_payload );
    }

    server_hello get_server_hello_from_ethernet_frame( const std::vector<uint8_t>& ethernet_frame ) {
        return get_server_hello_from_ethernet_frame( ethernet_frame.data() );
    }

    tls_over_tcp::tls_over_tcp( const four_tuple& four )
        : tcp_transfer( four ) {}

} // namespace ntk