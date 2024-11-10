import socket
import threading
from queue import Queue
from urllib.parse import urlparse

# Lock for thread-safe printing
print_lock = threading.Lock()

# Queue for multithreaded port scanning
queue = Queue()

# Dictionary to hold the results
open_ports = []

# Function to scan TCP ports
def scan_tcp_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set timeout for TCP connection attempts
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            with print_lock:
                open_ports.append((port, 'TCP', 'Open'))
    except socket.error:
        pass
    finally:
        sock.close()

# Function to scan UDP ports
def scan_udp_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)  # Set timeout for UDP connection attempts
    try:
        # Sending an empty packet
        sock.sendto(b'', (host, port))
        sock.recvfrom(1024)
        with print_lock:
            open_ports.append((port, 'UDP', 'Open'))
    except socket.timeout:
        pass  # Port is probably closed or unreachable
    except socket.error:
        pass
    finally:
        sock.close()

# Worker thread for multithreaded scanning
def worker(host):
    while not queue.empty():
        port = queue.get()
        scan_tcp_port(host, port)
        scan_udp_port(host, port)
        queue.task_done()

# Function to fill the queue with ports to scan
def fill_queue(port_range):
    for port in range(port_range[0], port_range[1] + 1):
        queue.put(port)

# Function to display the results in a table format
def display_results():
    print("\nPORT    TYPE    STATUS")
    print("----------------------")
    for port, protocol, status in open_ports:
        print(f"{port:<8}{protocol:<8}{status:<8}")

# Main function to run the scanner
def web_scanner():
    # Ask the user for the link
    url = input("Please provide a link (e.g., https://example.com): ")
    
    # Parse the URL to extract the hostname
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    
    if not host:
        print("Invalid URL. Please try again.")
        return
    
    print(f"It takes few sec.........Scanning ports on: {host}")
    
    # Define the port range (you can change this range as needed)
    port_range = (1, 1024)  # Scan ports 1 to 1024
    
    # Fill the queue with ports to scan
    fill_queue(port_range)
    
    # Create and start threads for faster scanning
    thread_count = 100  # Adjust thread count for faster scanning
    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(host,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    queue.join()
    
    # Display the results
    display_results()

# Run the scanner
if __name__ == "__main__":
    web_scanner()
