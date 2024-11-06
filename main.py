import time
import threading
import re
import scapy.all as scapy
from scapy.layers import http
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import urllib.parse

# Function to load and display past PCAP files in a background thread
def load_pcap_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        # Avoids freezing the UI
        threading.Thread(target=load_pcap_file_in_background, args=(file_path,)).start()

# Function to handle the actual loading process
def load_pcap_file_in_background(file_path):
    try:
        packets = scapy.rdpcap(file_path)  # Read the pcap file
        capture_output.delete(1.0, tk.END)  # Clear the text area
        capture_output.insert(tk.END, f"Loaded {len(packets)} packets from {file_path}\n")
        capture_output.see(tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Error loading PCAP file: {e}")

# Common SQL Injection and XSS attack payloads
sql_injection_payloads = [
    "' OR 1=1--", "'; DROP TABLE users--", "' AND '1'='1", "' UNION SELECT NULL, NULL--", "admin'--"
]
xss_payloads = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    '"><script>alert(1)</script>', '<iframe src="javascript:alert(1)"><iframe>'
]

# Global variables
packets = []  # List to store packets
sniffing_thread = None
sniffing = False
total_bytes = 0
start_time = None
bandwidth_label = None

# Format and label HTTP packet fields for readability
def display_http_packet(packet):
    http_layer = packet[http.HTTPRequest]

    # Formatting output similar to the terminal format
    output = "---------------------------------------------------\n"
    output += "[+] HTTP REQUEST >>>>>\n"
    output += f"{packet[scapy.IP].src} just requested\n"
    output += f"    GET {http_layer.Host.decode()} {http_layer.Path.decode()}\n"

    # Labeling individual parts
    output += "--------------------***HTTP Packet***--------------------\n"
    output += f"Key        Label\n"
    output += f"Accept     {http_layer.Accept}\n"
    output += f"Host       {http_layer.Host}\n"
    output += f"User_Agent {http_layer.User_Agent}\n"
    output += f"Method     {http_layer.Method}\n"
    output += f"Path       {http_layer.Path}\n"
    output += f"Http_Version {http_layer.Http_Version}\n"

    capture_output.insert(tk.END, output)
    capture_output.see(tk.END)

# Queue for holding the packets or strings to be displayed
from queue import Queue
packet_queue = Queue()

def process_sniffed_packet(packet):
    global total_bytes
    total_bytes += len(packet)  # Add to total bytes

    # Check if the packet contains HTTP requests
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet[http.HTTPRequest]
        src_ip = packet[scapy.IP].src
        host = http_layer.Host.decode()
        path = http_layer.Path.decode()

        # Display HTTP request details
        output = f"\n[+] HTTP REQUEST >>>>>>\n"
        output += f"{src_ip} just requested {host}{path}\n"
        capture_output.insert(tk.END, output)
        capture_output.see(tk.END)

        # Display HTTP headers
        for field, value in http_layer.fields.items():
            header_output = f"{field}: {value}\n"
            capture_output.insert(tk.END, header_output)
            capture_output.see(tk.END)

        # Check for SQL Injection or XSS in URL
        check_for_threats(url=f"{host}{path}", src_ip=src_ip)

        # Capture the Raw HTTP payload (for POST or data payloads)
        if packet.haslayer(scapy.Raw):
            raw_payload = packet[scapy.Raw].load.decode(errors='ignore')
            raw_output = f"[+] Raw Payload: {raw_payload}\n"
            capture_output.insert(tk.END, raw_output)
            capture_output.see(tk.END)

            # Check for SQL Injection or XSS in payload
            check_for_threats(payload=raw_payload, src_ip=src_ip)

    capture_output.see(tk.END)
    time.sleep(0.1)  # Delay to slow down packet display


# Function to detect SQL Injection and XSS in both URL and Payload
def check_for_threats(url=None, payload=None, src_ip="Unknown"):
    # Check URL for SQLi and XSS
    if url:
        decoded_url = urllib.parse.unquote(url)  # Decode URL
        for sql_payload in sql_injection_payloads:
            if sql_payload in decoded_url:
                threat_message = f"[!] SQL Injection Detected from {src_ip}: {decoded_url}\n"
                capture_output.insert(tk.END, threat_message, 'threat')
        
        for xss_payload in xss_payloads:
            if xss_payload in decoded_url:
                threat_message = f"[!] XSS Detected from {src_ip}: {decoded_url}\n"
                capture_output.insert(tk.END, threat_message, 'threat')
    
    # Check Payload for SQLi and XSS
    if payload:
        decoded_payload = urllib.parse.unquote(payload)  # Decode payload
        for sql_payload in sql_injection_payloads:
            if sql_payload in decoded_payload:
                threat_message = f"[!] SQL Injection Detected from {src_ip}: {decoded_payload}\n"
                capture_output.insert(tk.END, threat_message, 'threat')

        for xss_payload in xss_payloads:
            if xss_payload in decoded_payload:
                threat_message = f"[!] XSS Detected from {src_ip}: {decoded_payload}\n"
                capture_output.insert(tk.END, threat_message, 'threat')

    # Scroll to the end of the text widget
    capture_output.see(tk.END)


# Sniff packets on the specified interface
def sniff_packets(interface):
    global sniffing
    sniffing = True
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except Exception as e:
        messagebox.showerror("Error", f"Error capturing packets: {e}")
    finally:
        sniffing = False

# Function to start packet capture in a separate thread
def start_packet_capture():
    global start_time, sniffing_thread

    if sniffing:
        messagebox.showwarning("Warning", "Packet capture is already running!")
        return

    interface = interface_entry.get().strip()
    if not interface:
        messagebox.showerror("Error", "Please provide a valid network interface")
        return

    start_time = time.time()
    capture_output.delete(1.0, tk.END)  # Clear previous output
    messagebox.showinfo("Capture", f"Packet capturing started on {interface}...")

    # Start the packet capture in a separate thread
    sniffing_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniffing_thread.daemon = True  # Daemonize the thread to exit when the main thread exits
    sniffing_thread.start()



# Function to save captured packets
def save_capture():
    if not packets:
        messagebox.showwarning("Warning", "No packets captured yet!")
        return

    file_name = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
    if file_name:
        try:
            scapy.wrpcap(file_name, packets)
            messagebox.showinfo("Success", f"Packets saved to {file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving packets: {e}")

# Function to calculate and display bandwidth
def update_bandwidth():
    global total_bytes, start_time
    if start_time is None:
        return
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        bandwidth = (total_bytes * 8) / elapsed_time  # Convert to bits per second
        bandwidth_label.config(text=f"Bandwidth: {bandwidth / (1024 * 1024):.2f} Mbps")

# Function to load and display past PCAP files
def load_pcap_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        try:
            packets = scapy.rdpcap(file_path)
            capture_output.delete(1.0, tk.END)
            capture_output.insert(tk.END, f"Loaded {len(packets)} packets from {file_path}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error loading PCAP file: {e}")

# Function to show instructions on the "How to Use" page
def show_instructions():
    instructions = """
    1. Enter the network interface you want to monitor for packet capture.
    2. Click "Start Capture" to begin capturing network traffic.
    3. Detected SQL Injection and XSS threats will be flagged in the output.
    4. The bandwidth usage is calculated automatically.
    5. You can save captured packets to a .pcap file for later analysis.
    6. Load past .pcap files using the "Past PCAP Files" tab.
    """
    instruction_output.delete(1.0, tk.END)
    instruction_output.insert(tk.END, instructions)

# Initialize the main window
root = tk.Tk()
root.title("Network Traffic Analyzer")

# Maximize the window on startup
root.state('zoomed')  # This maximizes the window on launch (works on Windows)

# Create a notebook for different pages
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Create frames for each page
frame_capture = ttk.Frame(notebook, width=600, height=400)
frame_past_pcap = ttk.Frame(notebook, width=600, height=400)
frame_bandwidth = ttk.Frame(notebook, width=600, height=400)
frame_how_to_use = ttk.Frame(notebook, width=600, height=400)

# Add frames to notebook
notebook.add(frame_capture, text="Capture Packet")
notebook.add(frame_past_pcap, text="Past PCAP Files")
notebook.add(frame_bandwidth, text="Bandwidth Calculation")
notebook.add(frame_how_to_use, text="How to Use")

# Function to update the GUI with sniffed packets from the queue
def update_output():
    try:
        while not packet_queue.empty():
            output = packet_queue.get_nowait()
            capture_output.insert(tk.END, output)
            capture_output.see(tk.END)  # Scroll to the end
    except Exception as e:
        print(f"Error updating GUI: {e}")
    finally:
        # Schedule the next check for new packets
        root.after(100, update_output)  # Check every 100 ms

# Call this function when starting the GUI
root.after(100, update_output)  # Schedule the first check

# Capture Packet Page
tk.Label(frame_capture, text="Enter Interface for Packet Capture:", pady=10).pack()
interface_entry = tk.Entry(frame_capture)
interface_entry.pack(pady=5)
tk.Button(frame_capture, text="Start Capture", command=start_packet_capture).pack(pady=10)

# Scrolled text for real-time packet capture output
capture_output = scrolledtext.ScrolledText(frame_capture, height=20)
capture_output.pack(pady=10, padx=10, fill="both", expand=True)
capture_output.tag_config('threat', foreground='red')  # Red color for threats
tk.Button(frame_capture, text="Save Capture", command=save_capture).pack(pady=10)

# Past PCAP Files Page
tk.Label(frame_past_pcap, text="Open and view past PCAP files:").pack(pady=10)
tk.Button(frame_past_pcap, text="Open PCAP File", command=load_pcap_file).pack(pady=10)

# Bandwidth Calculation Page
bandwidth_label = tk.Label(frame_bandwidth, text="Bandwidth: 0 Mbps", font=("Arial", 16))
bandwidth_label.pack(pady=20)
tk.Button(frame_bandwidth, text="Update Bandwidth", command=update_bandwidth).pack(pady=10)

# How to Use Page
instruction_output = scrolledtext.ScrolledText(frame_how_to_use, height=20)
instruction_output.pack(pady=10, padx=10, fill="both", expand=True)
show_instructions()

# Start the GUI event loop
root.mainloop()