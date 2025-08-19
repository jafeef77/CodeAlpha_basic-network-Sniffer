
from scapy.all import sniff, IP, TCP, UDP, Raw
from termcolor import colored
import sys
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol_name = ""
        payload = ""
        protocol_color = "white"
        if TCP in packet:
            protocol_name = "TCP"
            protocol_color = "cyan"
            if Raw in packet:
                payload = packet[Raw].load.hex() # Use .hex() for a clean printout
        elif UDP in packet:
            protocol_name = "UDP"
            protocol_color = "magenta"
            if Raw in packet:
                payload = packet[Raw].load.hex()
        else:
            protocol_name = f"Protocol {ip_layer.proto}"
            protocol_color = "yellow"
        print("-" * 50)
        print(colored("Captured Packet:", "blue", attrs=['bold']))
        print(f"  {colored('🌐 IP:', 'green', attrs=['bold'])}      {colored(source_ip, 'green')} -> {colored(destination_ip, 'green')}")
        print(f"  {colored('🔗 Protocol:', 'white', attrs=['bold'])} {colored(protocol_name, protocol_color)}")
        if payload:
            print(f"  {colored('📦 Payload:', 'yellow', attrs=['bold'])}  {colored(payload, 'yellow')}")
        sys.stdout.flush()

def start_sniffing():
    print(colored("Starting packet sniffing. Press Ctrl+C to stop.", "red", attrs=['bold']))
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print(colored("\nStopping packet sniffing.", "red", attrs=['bold']))
    except Exception as e:
        print(colored(f"An error occurred: {e}", "red"))

if __name__ == "__main__":
    start_sniffing()

