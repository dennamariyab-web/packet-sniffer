
import socket
import struct
from datetime import datetime

# Create UDP socket for receiving packet data
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# For a beginner demonstration, use sample packet data
# rather than capturing live network traffic.

def analyze_packet(data):

    # Extract IP header
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])

    protocol = ip_header[6]

    source_ip = socket.inet_ntoa(ip_header[8])

    destination_ip = socket.inet_ntoa(ip_header[9])

    print("\n----- PACKET DETAILS -----")

    print("Source IP:", source_ip)

    print("Destination IP:", destination_ip)

    if protocol == 6:

        print("Protocol: TCP")

    elif protocol == 17:

        print("Protocol: UDP")

    else:

        print("Protocol:", protocol)


# Create sample IPv4 header for testing
def create_sample_packet():

    source = "192.168.1.10"

    destination = "192.168.1.20"

    header = struct.pack(
        "!BBHHHBBH4s4s",
        69, 0, 40, 1, 0, 64, 17, 0,
        socket.inet_aton(source),
        socket.inet_aton(destination)
    )

    return header + b"\x00" * 20


# Save packet details
def save_log(message):

    with open("network_log.txt", "a") as file:

        file.write(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + " | " + message + "\n"
        )


print("===== NETWORK PACKET SNIFFER =====")

packet = create_sample_packet()

analyze_packet(packet)

save_log("Sample UDP packet analyzed")

print("\nPacket details saved to network_log.txt")
