# Description

- Reconstructs TCP sessions from captured network packets.
- Extracts and decyprts TLS traffic.

# Build and Run Tests

Clone the directory, cd to main and set-up GoogleTest:
```
./setup_googletest.sh
```
Then build:
```
./build.sh
```
Then run the test executable:
```
sudo ./ntk_tests
```

# TCP Session Reconstruction
## Processing Pipeline

<p align="center">
  <img src="main/pipeline.jpg" width="600">
</p>

Each stage of the pipeline has a specific role and is loosely coupled, promoting testability and flexibility.

The pipeline can be split into three main sections:
- Packet capture and buffering.
- TCP session reconstruction
- TCP session offloading and post-processing.

### Packet Capture and Buffering
The <code>packet_listener</code> and <code>ring_buffer</code> work together to prevent packet-loss when network traffic is high or processing time is long.

<table>
  <tr>
    <td><code>packet_listener</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Captures raw packets from a network device using libpcap.<br><br>
      <strong>Design:</strong><br>
      - Takes a callback that controls the transfer of packets to a buffer.<br>
      - Callback should be light-weight to prevent packet loss.<br><br>  
      <strong>Key Members:</strong><br>
      - <code>m_callback</code>: called with each incoming packet.<br>
      - <code>m_device_name</code>, <code>m_filter_exp</code>: used to configure capture.<br>
    </td>
  </tr>
  <tr>
    <td><code>ring_buffer&lt;T,N&gt;</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Lock-free circular queue to buffer packets between threads.<br><br>
      <strong>Design:</strong><br>
      - Thread-safe via atomics.<br>
      - Pushes and pops are non-blocking.<br>
    </td>
  </tr> 
</table>

### TCP Session Reconstruction

<table>
  <tr>
    <td><code>tcp_live_stream_session</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Reconstructs TCP sessions from incoming packets.<br><br>
      <strong>Design:</strong><br>
      - Mainatains a set of <code>tcp_live_stream</code> objects, indexed by <code>four_tuple</code> ( IP/Port pairs).<br>
      - When a stream is marked complete, it's then offloaded to a queue.<br><br>
      <strong>Inferface:</strong><br>
      - Accepts packets through <code>feed()</code>.<br>
      - Offloads complete streams to a <code>transfer_queue_interface<tcp_live_stream></code>.<br>
    </td>
  </tr>
  <tr>
    <td><code>tcp_live_stream</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Models a single live TCP connection.<br><br>
      <strong>Design:</strong><br>
      - Accepts packets from a connection indicated by <code>m_four_tuple</code>.<br>
      - Tries to detect a valid TCP handshake and TCP termination sequence.<br>
      - Adds all packets between a valid handshake and termination sequence to <code>m_traffic</code>.<br>
      - Marks itself as complete when a valid TCP termination is detected.<br>
    </td>
  </tr> 
</table>

### TCP Session Offloading and Post-Processing

<table>
  <tr>
    <td><code>spmc_transfer_queue&lt;T,Filter&gt;</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Thread-safe single-producer-mutliple-consumer queue with optional filtering for handing off completed streams.<br><br>
      <strong>Design:</strong><br>
      - Implements <code>transfer_queue_interface<T></code>.<br>
      - Supports an optional <code>Filter</code> template parameter that determines whether to accept an item.<br>
      - Uses <code>std::queue</code>, <code>std::mutex</code>, and <code>std::condition_variable</code> to allow blocking or timed popping.<br><br>
    </td>
  </tr>
  <tr>
    <td><code>stream_processor</code></td>
    <td style="padding-left: 20px;">
      <strong>Purpose:</strong><br>
      Consumes completed TCP streams ( from the <code>spmc_transfer_queue</code> ) and processes them using a user-supplied callback.<br><br>
      <strong>Design:</strong><br>
      - Pulls <code>tcp_live_stream</code> objects from the queue using blocking or timed methods.<br>
      - When a stream is retrieved, it calls <code>m_callback(stream)</code> - where <code>m_callback</code> is user-supplied.<br>
    </td>
  </tr> 
</table>

## UML Diagram

<p align="center">
  <img src="images/processing_pipeline.jpg" width="1200">
</p>

## Example Usage

Here is an example of the above pipeline that captures HTTPS and writes the reconstructued TCP streams to file:

```cpp
#include <packet_listener.hpp>
#include <ring_buffer.hpp>
#include <tcp.hpp>
#include <spmc_queue.hpp>
#include <stream_processor.hpp>

std::string timestamp_filename() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm = *std::localtime( &now_c );
    std::ostringstream oss;
    oss << std::put_time( &tm, "%Y-%m-%d_%H-%M-%S" ) << ".txt";
    return oss.str();
}

int main() {

  using packet = std::vector<uint8_t>;
  const size_t ring_buffer_capacity = 1000;

  ntk::ring_buffer<packet,ring_buffer_capacity> ring_buff;

  // callback for packet_listener
  auto packet_callback = [&]( const struct pcap_pkthdr* header, const unsigned char* packet ) {
    std::vector<uint8_t> vec( packet, packet + header->caplen );
    ring_buff.push( vec );
  };

  // callback for stream_processor
  auto stream_callback = [&]( ntk::tcp_live_stream&& live_stream ) {
    std::string filename = timestamp_filename();
    ntk::output_stream_to_file( filename, live_stream );
  };

  ntk::packet_listener listener( "wlo1", "tcp port 443" );
  listener.start( packet_callback);

  ntk::tls_filter filter; // Filter example: only accept TLS traffic
  ntk::spmc_transfer_queue<ntk::tcp_live_stream,ntk::tls_filter> offload_queue( filter );
  ntk::tcp_live_stream_session live_stream_session( &offload_queue );

  ntk::stream_processor processor( &offload_queue, stream_callback );

  listener.start();
  processor.start();

  while ( true ) {
    std::vector<uint8_t> packet;
    if ( ring_buff.pop( packet ) ) {  
        live_stream_session.feed( packet );
    }
  }

  return 0;
}
```

# HTTPS Decryption and Extraction

The diagram below shows how <code>ntk</code> can be used to decrypt and extract HTTPS traffic.
<!--
<p align="center">
  <img src="images/tls.jpg" width="600">
</p>
-->

<div align="center">
  <picture>
    <source srcset="images/tls.jpg" media="(prefers-color-scheme: dark)">
    <source srcset="images/tls_.jpg" media="(prefers-color-scheme: light)">
    <img src="images/tls.jpg" width="600">
  </picture>
</div>

1. **Firefox** captures encrypted network traffic and logs SSL session keys to `sslkeys.log`.
2. **pcap** intercepts the traffic and feeds raw packets into the `ntk` processing stack.
3. Inside **`ntk`**, the following components are used:
   - **TCP session reconstruction**: Reassembles TCP streams from raw packets.
   - **TLS record parsing**: Extracts encrypted TLS records and metadata ( e.g., `client_random` ).
   - **SSL key extraction**: Useses `clinet_random` to extract the necessary session keys from `sslkeys.log`.
4. **OpenSSL** uses the session secrets and the metadata extracted from the handshake to decrypt the TLS records.
5. **HTTP payload extraction** pulls the decrypted content from the TLS records.
6. The resulting data ( e.g., `.ts` video segments ) is saved to disk.

```cpp
    // four: ( client_ip, server_ip, client_port, server_port )
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );

    auto client_tls_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_tls_records = ntk::extract_tls_records( server_payloads ).records;

    auto client_hello = ntk::get_client_hello( client_tls_records[ 0 ] );
    auto server_hello = ntk::get_server_hello( server_tls_records[ 0 ] );

    // session keys in "sslkey.log" are indexed with the client random
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );

    auto decrypted_server_tls_records = ntk::decrypt_tls_data(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,                // TLS version used in the session
        server_hello.cipher_suite,                  // this is used so OpenSSL can choose the correct cipher
        server_records_to_decrypt,                  // encrypted TLS records
        secrets,                                    // a map containing the session keys
        "SERVER_TRAFFIC_SECRET_0" );                // the label for the session-key needed for decrypting server->client traffic

    for ( auto& record : decrypted_server_tls_records ) {
        record.payload.pop_back();                  // the last byte of the decrypted payload is not part of the HTTP body
    }

    // skip over first two http responses
    ntk::http_response response = ntk::get_http_response(  decrypted_server_tls_records[ 2 ].payload  );

    for ( size_t i = 3; i < decrypted_server_tls_records.size(); ++i ) {
        response.body.insert( response.body.end(), decrypted_server_tls_records[ i ].payload.begin(), decrypted_server_tls_records[ i ].payload.end() );
    }

    ntk::write_payload_to_file( response.body, "segment.ts" );
```

<div align="center">
  <img src="main/output.gif" width="600"><br>
  <em><sub>segment.ts</sub></em>
</div>
