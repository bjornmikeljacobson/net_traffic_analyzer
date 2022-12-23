from scapy.all import *
from scapy.layers.inet import IP


def analyze_network_traffic(interface):
    # Sniff packets on the specified interface
    packets = sniff(iface=interface, count=10)

    # Analyze the packets
    analysis = {}
    for pckt in packets:
        # Extract the IP addresses and protocol
        src_ip = pckt[IP].src
        dst_ip = pckt[IP].dst
        protocol = pckt[IP].proto

    # Update the analysis
    if src_ip not in analysis:
        analysis[src_ip] = {
          "outgoing": {},
          "incoming": {},
      }
    if dst_ip not in analysis:
        analysis[dst_ip] = {
          "outgoing": {},
          "incoming": {},
      }
    if protocol not in analysis[src_ip]["outgoing"]:
        analysis[src_ip]["outgoing"][protocol] = 0
    if protocol not in analysis[dst_ip]["incoming"]:
        analysis[dst_ip]["incoming"][protocol] = 0
    analysis[src_ip]["outgoing"][protocol] += 1
    analysis[dst_ip]["incoming"][protocol] += 1

    # Return the analysis results
    return analysis


# Test the network traffic analyzer
def test_analyze_network_traffic():
    # Test with a valid interface
    result = analyze_network_traffic("Ethernet")
    assert result, "Error: analyze_network_traffic returned an empty result for a valid interface"

    # Test with an invalid interface
    # result = analyze_network_traffic("invalid_interface")
    # assert not result, "Error: analyze_network_traffic returned a result for an invalid interface"


test_analyze_network_traffic()
