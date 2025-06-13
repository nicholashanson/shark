#ifndef REQUESTS_HPP
#define REQUESTS_HPP

#include <curl/curl.h>
#include <string>
#include <iostream>

namespace ntk {

    bool make_request_curl( const std::string& url );

} // namespace ntk

#endif