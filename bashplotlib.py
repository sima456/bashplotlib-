import sys
import dpkt
import numpy as np
import matplotlib.pyplot as plt                       import bashplotlib.histogram as hist
import socket                                         def analyze_pcap(pcap_file):
    # Open PCAP file and read packets                     with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packets = list(pcap)

    # Count number of packets and bytes
    num_packets = len(packets)
    num_bytes = sum(len(p) for ts, p in packets)

    # Calculate packet sizes
    packet_sizes = np.array([len(p) for ts, p in packets])

    # Generate packet size histogram
    plt.figure()
    hist.plot_hist(packet_sizes, bincount=20, colour='blue')


    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.show()

    # Print summary information
    print(f"Number of packets: {num_packets}")
    print(f"Total bytes: {num_bytes}")
    print(f"Average packet size: {np.mean(packet_sizes)}")
    print(f"Standard deviation of packet size: {np.std(packet_sizes)}")

    # Find IP addresses and ports
    ips = set()
    ports = set()
    for ts, p in packets:
        eth = dpkt.ethernet.Ethernet(p)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            ips.add(socket.inet_ntoa(ip.src))
            ips.add(socket.inet_ntoa(ip.dst))
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                ports.add(tcp.sport)
                ports.add(tcp.dport)
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                ports.add(udp.sport)
                ports.add(udp.dport)

    # Print list of IPs and ports
    print("IP addresses:")
    for ip in ips:
        print(ip)
    print("Ports:")
    for port in ports:
        print(port)

    # Find potential IOCs
    iocs = set()
    for ts, p in packets:
        eth = dpkt.ethernet.Ethernet(p)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                    iocs.add((socket.inet_ntoa(ip.src), tcp.sport))
                    iocs.add((socket.inet_ntoa(ip.dst), tcp.dport))

    # Print list of potential IOCs
    print("Potential IOCs:")
    for ioc in iocs:
        print(ioc)

    # Add additional functionality as desired

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
