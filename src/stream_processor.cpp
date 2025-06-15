#include <stream_processor.hpp>

namespace ntk {

    stream_processor::stream_processor( transfer_queue_interface<tcp_live_stream>& queue,
                                        stream_callback callback ) 
        : m_queue( queue ), m_stop( false ), m_callback( callback ) {}

    void stream_processor::start() {
        m_thread = std::thread( &stream_processor::run, this );
    }

    void stream_processor::stop() {
        m_stop = true;
        if ( m_thread.joinable() ) m_thread.join();
    }

    void stream_processor::run() {
        while ( !m_stop ) {
            auto stream = m_queue.try_pop();

            if ( stream ) {
                process_stream( std::move( stream.value() ) );
            } else {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
        }
    }

    void stream_processor::process_stream( tcp_live_stream&& stream ) {
        m_callback( std::move( stream ) );
    }

} // namespace ntk