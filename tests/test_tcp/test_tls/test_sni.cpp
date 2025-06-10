#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <utils.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( LiveStreamTests, TLSGetSNIs ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_live_stream" ] );

    auto snis = ntk::get_snis( packet_data, "earthcam" );

    ASSERT_TRUE( !snis.empty() );
}

TEST( LiveStreamTests, TLSSni2Ip ) {

    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "earth_cam_live_stream" ] );

    auto sni_2_ip = ntk::get_sni_to_ip( packet_data );

    ASSERT_TRUE( !sni_2_ip.empty() );
    
    for ( auto [ sni, ip ] : sni_2_ip ) {
        std::cout << sni << ": " << static_cast<int>( ip ) << std::endl;
    }

    ASSERT_TRUE( sni_2_ip.contains( "videos-3.earthcam.com" ) );

    std::cout << ntk::ip_to_string( sni_2_ip[ "videos-3.earthcam.com" ] ) << std::endl;
}

TEST( PacketParsingTests, HasSNI ) {

    auto client_hello = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );

    ASSERT_TRUE( *ntk::has_sni( client_hello, "earthcam.com" ) );
}

TEST( PacketParsingTests, ClientHelloSNI ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_client_hello_v );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "tls_handshake" ], client_hello_line_numbers );

    ASSERT_EQ( client_hello_packets.size(), 1 );

    auto client_hello = ntk::get_client_hello_from_ethernet_frame( client_hello_packets[ 0 ] );

    auto sni_result = ntk::has_sni( client_hello, "earthcam.com" );

    if ( !sni_result ) {
        std::cerr << sni_result.error() << std::endl; 
    }

    ASSERT_TRUE( sni_result.value() );
}

TEST( LiveStreamTests, ClientHelloSNI ) {

    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::is_client_hello_v );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );

    std::vector<ntk::client_hello> client_hellos;

    for ( auto& client_hello_packet : client_hello_packets ) {
        auto tcp_payload = ntk::extract_payload_from_ethernet( client_hello_packet.data() );
        auto client_hello = ntk::get_client_hello( tcp_payload );
        client_hellos.push_back( client_hello );
    }

    ASSERT_TRUE( !client_hellos.empty() );

    bool found = false;
    for ( const auto& client_hello : client_hellos ) {
        auto result = ntk::sni_contains( client_hello, "earthcam" );
        if ( result.has_value() ) {
            std::cout << "SNI match result: " << *result << std::endl;
            if ( *result ) {
                found = true;
            }
        } else {
            std::cerr << "SNI parsing failed: " << result.error() << std::endl;
        }
    }   

    ASSERT_TRUE( found );
}
