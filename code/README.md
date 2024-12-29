# Covert Timing Channel Over LLC Layer

## Overview
This project implements a **covert timing channel** that encodes binary messages into **inter-arrival times** of packets at the Logical Link Control (LLC) layer. The sender encodes each bit into timing intervals between packets, and the receiver decodes the message by analyzing these intervals. This proof of concept demonstrates how timing channels can be used for covert communication over a network.

---

## Logic

### Encoding
- Each binary bit is encoded into a timing interval:
  - **Bit `0`**: A short random delay, ranging from `0` to `threshold_ms - error_ms`.
  - **Bit `1`**: A long random delay, ranging from `threshold_ms + error_ms` to `2 * threshold_ms`.
- These delays ensure a clear distinction between `0` and `1`, minimizing potential overlaps due to network jitter.

### Decoding
- The receiver measures the **inter-arrival times** of packets.
  - If the delay is less than or equal to `threshold_ms + error_ms`, it is interpreted as a `0`.
  - If the delay is greater than `threshold_ms + error_ms`, it is interpreted as a `1`.
- Once 8 bits are received, they are grouped and converted into a character. The process repeats until the full message is reconstructed.

### Timing Parameters
- **Threshold (`threshold_ms`)**: The central value that separates the timing ranges for `0` and `1`.
  - A value of `150 ms` was chosen for this project to balance throughput and robustness.
- **Error Margin (`error_ms`)**: Provides tolerance for handling network noise and jitter.
  - Set to `80 ms` to ensure clear separation between timing intervals.

---

## Results

- **Message Size**: 128 bits (16 characters).
- **Transmission Time**: Approximately 25.6 seconds.
- **Measured Capacity**: ~5 bits per second.

---

## Limitations

1. **Clock Resolution**: 
   - The accuracy of the timing intervals depends on the system clock's resolution. A low-resolution clock can cause inaccuracies in measuring inter-arrival times, leading to decoding errors.

2. **Network Jitter**:
   - Variability in network delays can blur the distinction between `0` and `1` intervals, especially if the actual delays deviate significantly from the configured ranges.

3. **Capacity vs. Robustness**:
   - Increasing the gap between `0` and `1` intervals improves robustness but reduces capacity. The chosen parameters represent a trade-off to achieve moderate throughput with reasonable accuracy.

4. **Threshold Sensitivity**:
   - The `threshold_ms` and `error_ms` values are environment-specific. Small deviations in these parameters can cause decoding errors, requiring careful tuning for each network setup.

---

## Conclusion

This project demonstrates a functional covert timing channel with a measured capacity of **5 bits per second**, achieved by encoding binary data into inter-arrival times of LLC packets. The results highlight the potential of timing-based communication while illustrating the challenges posed by clock resolution and network noise.

