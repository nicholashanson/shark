#ifndef MP4_HPP
#define MP4_HPP

#include <vector>

namespace ntk {

    struct file_type_box {]
        uint32_t length;
        uint32_t type;
        uint32_t major_brand;
        uint32_t minor_version;
        std::vector<uint32_t> compatible_brands;
    };

} // namespace ntk

#endif