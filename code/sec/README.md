# Enhanced TCP Covert Channel

This tool implements a covert channel using TCP window size manipulation to secretly transmit data between hosts.

## Features

- **Multiple Encoding Modes**:
  - **ASCII Mode**: Direct encoding of bytes in the window size field
  - **Binary Mode**: Stealthy encoding using bit patterns in normal-looking window sizes
  - **Custom Mode**: Non-linear transform for hiding data patterns

- **Stealth Features**:
  - Optional noise packet generation
  - Randomized packet timing
  - Varied TCP flags to appear like normal traffic

- **Error Correction**:
  - Optional checksums to verify data integrity
  - Detection of out-of-order and missing packets

## Requirements

- Python 3.x
- Root/sudo privileges (required for raw sockets)
- The `SECURENET_HOST_IP` and `INSECURENET_HOST_IP` environment variables must be set

## Usage

### Sender

```bash
sudo python3 enhanced_covert_tcp.py send <file_to_send> [options]
```

Options:
- `--mode {ascii,binary,custom}`: Encoding mode (default: ascii)
- `--window-base INT`: Base window size for encoding (default: 1000)
- `--port INT`: TCP port to use (default: 8888)
- `--delay FLOAT`: Delay between packets in seconds (default: 0.5)
- `--repeat INT`: Number of times to repeat transmission (default: 1)
- `--noise`: Add random noise packets to improve stealth
- `--error-correction`: Add error correction checksums
- `--logfile FILE`: Log file for sent data (default: sent_log.csv)

### Receiver

```bash
sudo python3 enhanced_covert_tcp.py receive [options]
```

Options:
- `--mode {ascii,binary,custom}`: Encoding mode (default: ascii)
- `--window-base INT`: Base window size for decoding (default: 1000)
- `--port INT`: TCP port to listen on (default: 8888)
- `--output FILE`: Output file for received data (default: received_data)
- `--timeout FLOAT`: Reception timeout in seconds
- `--logfile FILE`: Log file for received data (default: recv_log.csv)

## Examples

### Basic Usage

Sender:
```bash
sudo python3 enhanced_covert_tcp.py send secret_message.txt
```

Receiver:
```bash
sudo python3 enhanced_covert_tcp.py receive --output received_message.txt
```

### Stealth Mode

Sender:
```bash
sudo python3 enhanced_covert_tcp.py --mode binary --window-base 8192 send secret_message.txt --noise --error-correction --delay 0.3
```

Receiver:
```bash
sudo python3 enhanced_covert_tcp.py --mode binary --window-base 8192 receive --output received_message.txt
```

## How It Works

The tool uses the TCP window size field, normally used for flow control, to carry covert data between hosts:

1. **ASCII Mode**: Each byte of data is directly encoded as a window size value (0-255)
2. **Binary Mode**: Bytes are split into bits and distributed across typical window size ranges
3. **Custom Mode**: A non-linear transform is applied to make the pattern harder to detect

The implementation uses raw sockets to craft TCP packets with custom window sizes, allowing complete control over the TCP header fields.

## Security Considerations

This tool is for educational and research purposes only. Covert channels can be detected by network monitoring tools that analyze unusual patterns in window size values or packet timing. The `--noise` option helps reduce this risk by adding random legitimate-looking packets.

## Troubleshooting

If you encounter permissions errors, make sure you're running the script with sudo/root privileges.

If packets aren't being received, check:
1. Firewall rules that might block raw TCP packets
2. Ensure both sender and receiver use the same encoding mode and window-base value
3. Verify that the correct IP addresses are being used 