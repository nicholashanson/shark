#ifndef DECOMPRESS_HPP
#define DECOMPRESS_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <zlib.h>
#include <cstdint>

namespace ntk {

    std::string decompress_gzip( const std::vector<uint8_t>& compressed );

} // namespace ntk

#endif
