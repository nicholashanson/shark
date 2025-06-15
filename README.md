# Processing Pipeline

<p align="center">
  <img src="main/pipeline.jpg" width="600">
</p>

Each stage has a specific role and is loosely couply, promoting testability and flexibility.

### packet_listener
Purpose: caputes raw packets from a network device using libpcap.

Design:
- Takes a callback that controls the transfer of packets to a buffer.
- Callback should be light-weight to prevent packet loss.

## UML Diagram

<p align="center">
  <img src="main/processing_pipeline.jpg" width="1200">
</p>

## Packet Buffering

A ring-buffer is used for packet buffering. 


## TCP Connection Detection

### Handshake Detection

### Termination Detection


## Connection Filtering and Offloading

The SPMC

## Connection Processing

## Example Usage

```cpp
#include <packet_listener.hpp>
#include <ring_buffer.hpp>
#include <tcp.hpp>
#include <spmc_queue.hpp>
#include <stream_processor.hpp>

int main() {

  using packet = std::vector<uint8_t>;
  const size_t ring_buffer_capacity = 1000;

  ntk::ring_buffer<packet,ring_buffer_capacity> ring_buff;

  auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
    std::vector<uint8_t> vec( packet, packet + header->caplen );
`   ring_buff.push( vec );
  };

  auto stream_callback = [&]( ntk::tcp_live_stream&& live_stream ) {
    ntk::out
  };

  ntk::packet_listener listener( "wlo1", "tcp port 443" );
  listener.start( packet_callback);

  ntk::tcp_live_stream_session live_stream_session;

  ntk::tls_filter filter;
  ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
  ntk::tcp_live_stream_session live_stream_session( &offload_queue );

  

  return 0;
}
```

<p align="center">
  <img src="main/output.gif" width="600">
</p>
