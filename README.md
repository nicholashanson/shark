# UML Diagram

<p align="center">
  <img src="main/processing_pipeline.jpg" width="1200">
</p>

# Processing Pipeline
## Packet Capture

The packet_listener thread transfers pakcets captured by pcap from kernel-space to user-space.
The packet_listener takes a callback that controls the transfer of packets to a buffer.
The callback should be light-weight to prevent packet loss. Network traffic is not constant, 
and buffering helps us ensure all packets are captured.

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
```

<p align="center">
  <img src="main/output.gif" width="600">
</p>
