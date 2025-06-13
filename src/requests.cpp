#include <requests.hpp>

namespace ntk {

    bool make_request_curl( const std::string& url ) {

        CURL* curl = curl_easy_init();

        if ( !curl ) {
            std::cerr << "Failed to initialize curl\n";
            return false;
        }

        curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
        curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, nullptr );
        curl_easy_setopt( curl, CURLOPT_TIMEOUT, 10L );

        CURLcode res = curl_easy_perform( curl );
        if ( res !=  CURLE_OK ) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror( res ) << "\n";
            curl_easy_cleanup( curl );
            return false;
        }

        curl_easy_cleanup( curl );

        return true;
    };

} // namespace ntk
