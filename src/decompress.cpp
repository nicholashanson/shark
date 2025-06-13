#include <decompress.hpp> 

namespace ntk {
    
    std::string decompress_gzip( const std::vector<uint8_t>& compressed ) {

        z_stream stream{};
        stream.next_in = const_cast<Bytef*>( compressed.data() );
        stream.avail_in = compressed.size();

        if ( inflateInit2( &stream, 16 + MAX_WBITS ) != Z_OK ) {
            throw std::runtime_error( "inflateInit2 failed" );
        }

        char out_buffer[ 32768 ];
        std::string out_string;

        int ret;

        do {
            stream.next_out = reinterpret_cast<Bytef*>( out_buffer );
            stream.avail_out = sizeof( out_buffer );

            ret = inflate( &stream, 0 );

            if ( out_string.size() < stream.total_out ) {
                out_string.append( out_buffer, stream.total_out - out_string.size() );
            }
        } while ( ret == Z_OK );

        inflateEnd( &stream );

        if ( ret != Z_STREAM_END ) {
            throw std::runtime_error( "inflate did not reach stream end" );
        }

        return out_string;
    }

} // namespace ntk