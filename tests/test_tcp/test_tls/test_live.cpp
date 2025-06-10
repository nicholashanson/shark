#include <gtest/gtest.h>

#include <pcap.h>

#include <span>
#include <cstdint>

#include <packet_listener.hpp>
#include <tcp.hpp>
#include <requests.hpp>
#include <utils.hpp>

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
}