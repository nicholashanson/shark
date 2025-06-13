#include <packet_listener.hpp>

namespace ntk {

    packet_listener::packet_listener( const char* device_name, const char* filter_exp ) 
        : m_device_name( device_name ), m_filter_exp( filter_exp ), m_handle( nullptr ) {}
        
    packet_listener::~packet_listener() {
        stop();
    }

    bool packet_listener::start( packet_callback callback ) {

        if ( m_capturing ) return false; 

        m_callback = callback;
        m_handle = open_device( m_device_name );
        apply_filter( m_handle, m_filter_exp );

        m_capturing = true;

        m_capture_thread = std::thread( [ this ]() {

            run_capture_loop( m_handle,
                []( u_char* user, const struct pcap_pkthdr* h, const u_char* bytes ) {
                    auto* self = reinterpret_cast<packet_listener*>( user );
                    if ( self->m_callback ) {
                        self->m_callback( h, bytes );
                    }
                }, 
                reinterpret_cast<u_char*>( this ) );
        });

        return true;
    }

    void packet_listener::stop() {

        if ( m_capturing ) {
            pcap_breakloop( m_handle );
            if ( m_capture_thread.joinable() ) {
                m_capture_thread.join();
            }
            pcap_close( m_handle );
            m_handle = nullptr;
            m_capturing = false;
        }
    }

} // namespace ntk

