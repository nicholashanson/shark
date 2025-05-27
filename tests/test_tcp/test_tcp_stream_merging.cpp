#include <gtest/gtest.h>

#include <tcp.hpp>

TEST( PacketParsingTests, TCPStreamMerging ) {

    ntk::tcp_stream overlapping_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },    
        { 1004, { 'E', 'F', 'G' } },          
        { 1002, { 'C', 'D', 'E', 'F' } },     
        { 1010, { 'H', 'I' } },              
        { 1003, { 'D', 'E', 'F' } }            
    };

    ntk::tcp_stream actual_merged_stream = ntk::merge_tcp_stream_non_overlapping( overlapping_stream );

    ntk::tcp_stream expected_merged_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },
        { 1004, { 'E', 'F' } },
        { 1006, { 'G' } },
        { 1010, { 'H', 'I' } }
    };

    ASSERT_EQ( actual_merged_stream, expected_merged_stream );
}