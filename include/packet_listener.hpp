#ifndef PACKET_LISTENER_HPP
#define PACKET_LISTENER_HPP

#include <pcap.h>
#include <thread>
#include <functional>
#include <atomic>
#include <iostream>

#include <constants.hpp>
#include <packet_capture.hpp>

namespace ntk {

    using packet_callback = std::function<void( const struct pcap_pkthdr*, const unsigned char* )>;
    
    class packet_listener {

        public: 
            packet_listener( const char* device_name, const char* filter_exp );
            ~packet_listener();
            bool start( packet_callback callback );
            void stop();
            bool is_capturing() const;
        private:
            const char* m_device_name;
            const char* m_filter_exp;
            packet_callback m_callback;
            pcap_t* m_handle;
            std::thread m_capture_thread;
            std::atomic<bool> m_capturing;
    };

} // namespace ntk

#endif 
