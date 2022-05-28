from scapy.all import sr,sr1,IP,TCP,RandShort,RandIP
import sys


if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} [IP-Address] [Start Port] [End Port]")
    sys.exit(0)

dst_ip = str(sys.argv[1])
str_port = int(sys.argv[2])
end_port = int(sys.argv[3])
open_port_list = []

def scan_ports(target,start_port,end_port):
    for port in range(start_port,end_port+1):
        pkt = IP(dst=target)/TCP(dport=port,flags="S")
        response = sr1(pkt,timeout=0.5,verbose=0)
        if response is None:
            print(f"Has TCP layer: False, response = None, port:{port}")
            continue
            
        print(f"Has TCP layer {response.haslayer(TCP)}, response = '{response.getlayer(TCP).flags}', port: {port} , OPEN!!")
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_port_list.append(port)
        sr(IP(dst=target)/TCP(dport=response.sport,flags="R"),timeout=0.5,verbose=0)
    print("Scan is complete.")
    if(open_port_list):
        print(f"Open ports: {open_port_list}")
    else:
        print("No open ports.")


if str_port == end_port:
    print("Entered same start and end ports, incrementing the ending port by 1")
    end_port += 1
    print(f"Scanning TCP ports for {dst_ip} from {str_port} to {end_port}:")
else:
    print(f"Scanning TCP ports for {dst_ip} from {str_port} to {end_port}:")

scan_ports(dst_ip,str_port,end_port)