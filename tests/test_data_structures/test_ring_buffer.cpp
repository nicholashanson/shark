#include <gtest/gtest.h>

#include <ring_buffer.hpp>

TEST( DataStructureTests, RingBufferPushAndPop ) {

    ntk::ring_buffer<int,4> buf;
    
    EXPECT_TRUE( buf.push( 10 ) );

    int val;

    EXPECT_TRUE( buf.pop( val ) );
    EXPECT_EQ( val, 10 );

}

TEST( DataStructureTests, RingBufferFIFOOrder ) {

    ntk::ring_buffer<int,4> buf;
    buf.push( 1 ); 
    buf.push( 2 ); 
    buf.push( 3 );

    int val;
    buf.pop( val ); EXPECT_EQ( val, 1 );
    buf.pop( val ); EXPECT_EQ( val, 2 );
    buf.pop( val ); EXPECT_EQ( val, 3 );
}

TEST( DataStructureTests, RingBufferOverfillBuffer ) {

    ntk::ring_buffer<int,4> buf;

    EXPECT_TRUE( buf.push( 1 ) );
    EXPECT_TRUE( buf.push( 2 ) );
    EXPECT_TRUE( buf.push( 3 ) );

    EXPECT_FALSE( buf.push( 4 ) );
}

TEST( DataStructureTests, RingBufferUnderflowBuffer ) {

    ntk::ring_buffer<int,4> buf;

    int val;
    
    EXPECT_FALSE( buf.pop( val ) );
}

TEST( DataStructureTests, RingBufferWrapAround ) {

    ntk::ring_buffer<int,4> buf;
    buf.push( 1 );
    buf.push( 2 );
    buf.push( 3 );

    int val;
    buf.pop( val ); EXPECT_EQ( val, 1 );
    buf.push( 4 ); 

    buf.pop( val ); EXPECT_EQ( val, 2 );
    buf.pop( val ); EXPECT_EQ( val, 3 );
    buf.pop( val ); EXPECT_EQ( val, 4 );
}
