#ifndef SPMC_QUEUE_HPP
#define SPMC_QUEUE_HPP

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <concepts>

namespace ntk {

    template<typename Filter,typename T>
    concept FilterConcept = requires( Filter f, T t ) {
        { f( t ) } -> std::convertible_to<bool>;
    };

    template<typename T>
    struct accept_all {
        bool operator()( const T& ) const {
            return true;
        } 
    };

    template <typename T>
    class transfer_queue_interface {
        public:
            virtual ~transfer_queue_interface() = default;
            virtual void push(const T& item) = 0;
            virtual std::optional<T> pop_for( std::chrono::milliseconds time_out ) = 0;
            virtual std::optional<T> try_pop() = 0;
    };

    template<typename T,typename Filter = accept_all<T>>
        requires FilterConcept<Filter,T>
    class spmc_transfer_queue : public transfer_queue_interface<T>  {

        public:
            spmc_transfer_queue() = default;
            spmc_transfer_queue( Filter filter );

            void push( const T& item );
            std::optional<T> pop_for( std::chrono::milliseconds time_out );
            std::optional<T> try_pop();
            bool empty() const;

        private:
            std::queue<T> m_queue;
            mutable std::mutex m_mutex;
            std::condition_variable m_cv;
            Filter m_filter;
    };

    template<typename T,typename Filter> 
        requires FilterConcept<Filter,T>
    spmc_transfer_queue<T,Filter>::spmc_transfer_queue( Filter filter ) 
        : m_filter( filter ) {}

    template<typename T,typename Filter>
        requires FilterConcept<Filter,T> 
    void spmc_transfer_queue<T,Filter>::push( const T& item ) {
        if ( !m_filter( item ) ) return;
        {
            std::lock_guard<std::mutex> lock( m_mutex );
            m_queue.push( item );
        }
        m_cv.notify_one(); 
    }

    template<typename T,typename Filter>
        requires FilterConcept<Filter,T>
    std::optional<T> spmc_transfer_queue<T,Filter>::pop_for( std::chrono::milliseconds time_out ) {
        std::unique_lock<std::mutex> lock( m_mutex );
        if ( !m_cv.wait_for( lock, time_out, [ this ] { return !m_queue.empty(); } )) {
            return std::nullopt;
        } 
        T item = std::move( m_queue.front() );
        m_queue.pop();
        return item;
    }

    template<typename T,typename Filter>
        requires FilterConcept<Filter,T>
    std::optional<T> spmc_transfer_queue<T,Filter>::try_pop() {
        std::lock_guard<std::mutex> lock( m_mutex );
        if ( m_queue.empty() ) return std::nullopt;
        T item = std::move( m_queue.front() );
        m_queue.pop();
        return item;
    }

    template<typename T,typename Filter>
        requires FilterConcept<Filter,T>
    bool spmc_transfer_queue<T,Filter>::empty() const {
        std::lock_guard<std::mutex> lock( m_mutex );
        return m_queue.empty();
    }

} // namespace ntk

#endif


