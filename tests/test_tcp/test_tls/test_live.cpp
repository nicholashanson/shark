#include <gtest/gtest.h>

#include <pcap.h>

#include <span>
#include <cstdint>

#include <packet_listener.hpp>
#include <ring_buffer.hpp>
#include <spmc_queue.hpp>
#include <tls.hpp>
#include <requests.hpp>
#include <utils.hpp>

#include <test_constants.hpp>

TEST( LiveStreamTests, Google ) {

    ntk::tcp_live_stream_session live_stream_session;

    std::mutex mtx;
    std::condition_variable cv;
    bool finished = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( live_stream_session.number_of_completed_transfers() != 0 ) {
            std::lock_guard<std::mutex> lock( mtx );
            finished = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    ntk::make_request_curl( "https://www.google.com" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool completed = cv.wait_for( lock, std::chrono::seconds( 10 ), [&]() { return finished; } );
        ASSERT_TRUE( completed );
    }
    
    listener.stop();

    ASSERT_TRUE( live_stream_session.number_of_completed_transfers() != 0 );

    auto& live_streams = ntk::tcp_live_stream_session_friend_helper::live_streams( live_stream_session );

    ASSERT_EQ( live_streams.size(), 1 );

    auto& handshake = ntk::tcp_live_stream_friend_helper::handshake_feed( live_streams.front() ).m_handshake;
    auto& termination = ntk::tcp_live_stream_friend_helper::termination_feed( live_streams.front() ).m_termination;

    ASSERT_TRUE( ntk::is_valid_handshake( handshake ) );
    ASSERT_TRUE( ntk::is_valid_fin_ack_fin_ack( termination ) );

    ASSERT_TRUE( live_streams.front().traffic_contains( ntk::is_client_hello_v ) );

    ntk::tls_live_stream tls_stream( live_streams.front() );
}

TEST( LiveStreamTests, OffloadQueueTestFilter ) {

    ntk::tls_filter filter;

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( !offload_queue.empty() ) {
            std::lock_guard<std::mutex> lock( mtx );
            ready = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    ntk::make_request_curl( "https://www.google.com" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool notified = cv.wait_for( lock, std::chrono::seconds( 5 ), [&] { return ready; } );
        ASSERT_TRUE( notified );
    }

    listener.stop();

    ASSERT_FALSE( offload_queue.empty() );
    auto maybe_stream = offload_queue.try_pop();
    ASSERT_TRUE( maybe_stream.has_value() );

    const auto& stream = maybe_stream.value();
    ASSERT_TRUE( stream.traffic_contains( ntk::is_client_hello_v ) );
}

TEST( LiveStreamTests, FireFoxGoogleTLSFilter ) {

    ntk::tls_filter filter;

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( !offload_queue.empty() ) {
            std::lock_guard<std::mutex> lock( mtx );
            ready = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    std::system( "firefox --headless https://www.google.com & sleep 5; pkill firefox" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool notified = cv.wait_for( lock, std::chrono::seconds( 5 ), [&] { return ready; } );
        ASSERT_TRUE( notified );
    }

    listener.stop();

    ASSERT_FALSE( offload_queue.empty() );
    auto maybe_stream = offload_queue.try_pop();
    ASSERT_TRUE( maybe_stream.has_value() );

    const auto& stream = maybe_stream.value();
    ASSERT_TRUE( stream.traffic_contains( ntk::is_client_hello_v ) );

    ntk::tls_live_stream tls_stream( stream );
    std::cout << tls_stream.get_sni() << std::endl;
}

TEST( LiveStreamTests, FireFoxEarthCamTLSFilter ) {

    ntk::tls_filter filter;

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( !offload_queue.empty() ) {
            std::lock_guard<std::mutex> lock( mtx );
            ready = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    std::system( "firefox --headless https://www.earthcam.com/usa/florida/fortlauderdale/marina/?cam=lauderdalemarina & sleep 5; pkill firefox" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool notified = cv.wait_for( lock, std::chrono::seconds( 5 ), [&] { return ready; } );
        ASSERT_TRUE( notified );
    }

    listener.stop();

    ASSERT_FALSE( offload_queue.empty() );
    auto maybe_stream = offload_queue.try_pop();
    ASSERT_TRUE( maybe_stream.has_value() );

    const auto& stream = maybe_stream.value();
    ASSERT_TRUE( stream.traffic_contains( ntk::is_client_hello_v ) );

    ntk::tls_live_stream tls_stream( stream );
    ASSERT_EQ( tls_stream.get_sni(), "static.earthcam.com" );
}

TEST( LiveStreamTests, FireFoxEarthCamSNIFilter ) {

    ntk::sni_filter filter( "earthcam" );

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::sni_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( !offload_queue.empty() ) {
            std::lock_guard<std::mutex> lock( mtx );
            ready = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    std::system( "firefox --headless https://www.earthcam.com/usa/florida/fortlauderdale/marina/?cam=lauderdalemarina & sleep 5; pkill firefox" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool notified = cv.wait_for( lock, std::chrono::seconds( 10 ), [&] { return ready; } );
        ASSERT_TRUE( notified );
    }

    listener.stop();

    ASSERT_FALSE( offload_queue.empty() );
    auto maybe_stream = offload_queue.try_pop();
    ASSERT_TRUE( maybe_stream.has_value() );

    const auto& stream = maybe_stream.value();
    ASSERT_TRUE( stream.traffic_contains( ntk::is_client_hello_v ) );
}

TEST( LiveStreamTests, FireFoxEarthCamStrictSNIFilter ) {

    ntk::sni_filter filter( "videos-3.earthcam.com" );

    ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::sni_filter> offload_queue( filter );
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;

    auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
        std::vector<uint8_t> vec( packet, packet + header->caplen );
        live_stream_session.feed( vec );
        if ( !offload_queue.empty() ) {
            std::lock_guard<std::mutex> lock( mtx );
            ready = true;
            cv.notify_one();
        }
    };

    ntk::packet_listener listener( "wlo1", "tcp port 443" );
    ASSERT_TRUE( listener.start( packet_callback) );

    std::system( "firefox --headless https://www.earthcam.com/usa/florida/fortlauderdale/marina/?cam=lauderdalemarina & sleep 5; pkill firefox" );

    {
        std::unique_lock<std::mutex> lock( mtx );
        bool notified = cv.wait_for( lock, std::chrono::seconds( 10 ), [&] { return ready; } );
        ASSERT_TRUE( notified );
    }

    listener.stop();

    ASSERT_FALSE( offload_queue.empty() );
    auto maybe_stream = offload_queue.try_pop();
    ASSERT_TRUE( maybe_stream.has_value() );

    const auto& stream = maybe_stream.value();
    ASSERT_TRUE( stream.traffic_contains( ntk::is_client_hello_v ) );
}



