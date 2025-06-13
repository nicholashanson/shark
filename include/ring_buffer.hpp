#ifndef RING_BUFFER_HPP
#define RING_BUFFER_HPP

#include <cstddef>

namespace ntk {

    template<typename T,size_t N> 
    class ring_buffer {

        public:
            ring_buffer();
            bool push( const T& item );
            bool pop( T& item ); 
        private:
            std::array<T,N> m_buffer;
            std::atomic<size_t> m_head;
            std::atomic<size_t> m_tail;
    };

    template<typename T,size_t N>
    ring_buffer<T,N>::ring_buffer()
        : m_head( 0 ), m_tail( 0 ) {}

    template<typename T,size_t N>
    bool ring_buffer<T,N>::push( const T& item ) {
        size_t head = m_head.load( std::memory_order_relaxed );
        size_t tail = m_tail.load( std::memory_order_acquire );
        size_t next_head = ( head + 1 ) % N;
        if ( next_head == tail ) return false;
        m_buffer[ head ] = item;
        m_head.store( next_head, std::memory_order_release );
        return true;
    }

    template<typename T,size_t N>
    bool ring_buffer<T,N>::pop( T& item ) {
        size_t head = m_head.load( std::memory_order_acquire );
        size_t tail = m_tail.load( std::memory_order_relaxed );
        if ( head == tail ) return false;
        item = m_buffer[ tail ];
        m_tail.store( ( tail + 1 ) % N, std::memory_order_release );
        return true;
    }

} // namespace ntk

#endif
