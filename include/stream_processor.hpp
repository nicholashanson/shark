#ifndef STREAM_PROCESSOR_HPP
#define STREAM_PROCESSOR_HPP

#include <thread>
#include <atomic>
#include <functional>

#include <tcp.hpp>
#include <spmc_queue.hpp>

namespace ntk {

    class stream_processor {

        public:

            using stream_callback = std::function<void(tcp_live_stream&&)>;

            stream_processor(
                transfer_queue_interface<tcp_live_stream>& queue,
                stream_callback callback
            );

            void start();
            void stop();
        private:
            void run();
            void process_stream( tcp_live_stream&& stream );

            transfer_queue_interface<tcp_live_stream>& m_queue;
            std::thread m_thread;
            std::atomic<bool> m_stop;
            stream_callback m_callback;
    };

} // namespace ntk

#endif