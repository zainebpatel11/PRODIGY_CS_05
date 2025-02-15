import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP
import threading

# Global control variable
sniffing = False

# Colors for protocol display
protocol_colors = {
    'TCP': 'lightblue',
    'UDP': 'lightgreen',
    'ICMP': 'lightyellow',
    'Other': 'lightgray'
}

# Packet processing function
def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, 'Other')
        info = f"Source: {src} -> Destination: {dst} | Protocol: {proto_name}"

        text_display.configure(state='normal')
        text_display.insert(tk.END, info + '\n', proto_name)
        text_display.configure(state='disabled')

# Start sniffing thread
def start_sniffing():
    global sniffing
    if sniffing:
        return

    sniffing = True
    filter_choice = filter_var.get()
    filter_string = '' if filter_choice == 'All' else filter_choice.lower()

    text_display.configure(state='normal')
    text_display.delete(1.0, tk.END)
    text_display.configure(state='disabled')

    try:
        sniff_thread = threading.Thread(target=lambda: sniff(filter=filter_string, prn=packet_callback, store=0, stop_filter=lambda _: not sniffing))
        sniff_thread.start()
        status_label.config(text="Status: Sniffing...", fg="green")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start sniffing: {e}")

# Stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", fg="red")

# GUI Setup
root = tk.Tk()
root.title("Interactive Network Packet Analyzer")
root.geometry("800x500")

# Create protocol-specific tags for color coding
text_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=90)
text_display.tag_configure('TCP', foreground='blue')
text_display.tag_configure('UDP', foreground='green')
text_display.tag_configure('ICMP', foreground='orange')
text_display.tag_configure('Other', foreground='gray')
text_display.configure(state='disabled')
text_display.pack(pady=10)

# Control Panel
control_frame = tk.Frame(root)
control_frame.pack(pady=5)

filter_label = tk.Label(control_frame, text="Protocol Filter:")
filter_label.grid(row=0, column=0, padx=5)

filter_var = tk.StringVar(value="All")
protocols = ["All", "TCP", "UDP", "ICMP"]
filter_menu = ttk.Combobox(control_frame, textvariable=filter_var, values=protocols, state="readonly")
filter_menu.grid(row=0, column=1, padx=5)

start_button = tk.Button(control_frame, text="Start Sniffing", command=start_sniffing, bg="lightgreen")
stop_button = tk.Button(control_frame, text="Stop Sniffing", command=stop_sniffing, bg="salmon")
start_button.grid(row=0, column=2, padx=5)
stop_button.grid(row=0, column=3, padx=5)

status_label = tk.Label(root, text="Status: Ready", fg="blue")
status_label.pack(pady=5)

# Run the application
root.mainloop()
