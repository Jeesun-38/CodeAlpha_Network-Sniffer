import scapy.all as scapy
from scapy.layers import http
import psutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import subprocess
import os
import time
import datetime

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Zetsu - Packet Sniffer")
        self.root.geometry("1000x650")
        self.root.configure(bg="#1e1e2f")

        self.sniffing = False
        self.packet_count = 0
        self.log_lines = []

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_filename = f"pcket_log_{timestamp}.txt"
        self.log_file = open(self.log_filename, "a")

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", foreground="#ffffff", background="#1e1e2f", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TCombobox", padding=4)

        title = tk.Label(self.root, text="🕵️ Zetsu - Network Packet Sniffer 🔓", font=("Segoe UI", 20, "bold"), fg="#ffcc00", bg="#1e1e2f")
        title.pack(pady=15)

        frame = tk.Frame(self.root, bg="#1e1e2f")
        frame.pack(pady=10)

        ttk.Label(frame, text="Select Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_combo = ttk.Combobox(frame, width=30, state="readonly")
        self.interface_combo.grid(row=0, column=1, padx=5)
        self.interface_combo['values'] = self.get_interfaces()

        self.raw_var = tk.BooleanVar()
        raw_check = ttk.Checkbutton(frame, text="Show Raw Payloads", variable=self.raw_var)
        raw_check.grid(row=0, column=2, padx=10)

        ttk.Label(frame, text="Filter Packet Type:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.protocol_var = tk.StringVar()
        self.protocol_filter = ttk.Combobox(frame, textvariable=self.protocol_var, state="readonly", values=["All", "HTTP", "TCP", "UDP", "DNS"])
        self.protocol_filter.current(0)
        self.protocol_filter.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.start_btn = tk.Button(frame, text="Start Sniffing", bg="#28a745", fg="white", font=("Segoe UI", 10, "bold"), command=self.toggle_sniffing)
        self.start_btn.grid(row=0, column=3, padx=5)

        self.export_btn = tk.Button(frame, text="Export Logs", command=self.export_logs)
        self.export_btn.grid(row=1, column=3, padx=5, pady=5)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(frame, textvariable=self.search_var, width=30)
        search_entry.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        search_entry.insert(0, "Filter by keyword")

        self.log_output = scrolledtext.ScrolledText(self.root, width=120, height=25, state="disabled", font=("Consolas", 9), bg="#111", fg="#00ffcc", insertbackground="white")
        self.log_output.pack(pady=10, padx=10)
        self.log_output.tag_config("cred", foreground="red", font=("Consolas", 9, "bold"))
        self.log_output.tag_config("http", foreground="#00ffcc")
        self.log_output.tag_config("info", foreground="#cccccc")
        self.log_output.tag_config("tcp", foreground="#66ccff")
        self.log_output.tag_config("udp", foreground="#99ff99")
        self.log_output.tag_config("dns", foreground="#ffcc66")

        self.status_label = tk.Label(self.root, text="Packets captured: 0", bg="#1e1e2f", fg="white")
        self.status_label.pack(side="bottom", fill="x")

        self.start_mitmproxy()

    def get_interfaces(self):
        return list(psutil.net_if_addrs().keys())

    def toggle_sniffing(self):
        if not self.sniffing:
            selected = self.interface_combo.get()
            if not selected:
                messagebox.showerror("Error", "Please select a network interface.")
                return
            self.sniffing = True
            self.start_btn.config(text="Stop Sniffing", bg="#dc3545")
            thread = threading.Thread(target=self.start_sniffing, args=(selected,), daemon=True)
            thread.start()
        else:
            self.sniffing = False
            self.start_btn.config(text="Start Sniffing", bg="#28a745")

    def log(self, text, tag="info"):
        if self.search_var.get().lower() in text.lower():
            self.log_output.config(state="normal")
            self.log_output.insert(tk.END, text + "\n", tag)
            self.log_output.yview(tk.END)
            self.log_output.config(state="disabled")
        else:
            self.log_output.config(state="normal")
            self.log_output.insert(tk.END, text + "\n", tag)
            self.log_output.yview(tk.END)
            self.log_output.config(state="disabled")

        self.log_file.write(text + "\n")
        self.log_lines.append(text)

    def update_status(self):
        self.status_label.config(text=f"Packets captured: {self.packet_count}")

    def start_sniffing(self, interface):
        try:
            scapy.sniff(iface=interface, store=False, prn=self.process_packet, stop_filter=lambda x: not self.sniffing)
        except PermissionError:
            self.log("❗ Permission denied. Run with sudo/admin rights.", "cred")
            self.toggle_sniffing()
        except Exception as e:
            self.log(f"❗ Error: {e}", "cred")
            self.toggle_sniffing()

    def process_packet(self, packet):
        protocol_filter = self.protocol_var.get()

        if not packet.haslayer(scapy.IP):
            return

        ip = packet[scapy.IP].src

        if packet.haslayer(http.HTTPRequest):
            if protocol_filter not in ["All", "HTTP"]:
                return
            method = packet[http.HTTPRequest].Method.decode()
            host = packet[http.HTTPRequest].Host.decode()
            path = packet[http.HTTPRequest].Path.decode()
            self.log(f"🔓 [HTTP] {ip} → {method} http://{host}{path}", "http")

        elif packet.haslayer(scapy.TCP) and protocol_filter in ["All", "TCP"]:
            dport = packet[scapy.TCP].dport
            self.log(f"🟢 [TCP] {ip} → Port {dport}", "tcp")

        elif packet.haslayer(scapy.UDP) and protocol_filter in ["All", "UDP"]:
            dport = packet[scapy.UDP].dport
            self.log(f"🟢 [UDP] {ip} → Port {dport}", "udp")

        elif packet.haslayer(scapy.DNS) and protocol_filter in ["All", "DNS"]:
            dns_layer = packet[scapy.DNS]
            if dns_layer.qr == 0 and dns_layer.qd is not None:
                query_name = dns_layer.qd.qname.decode(errors="ignore")
                self.log(f"🌐 [DNS] {ip} queried for {query_name}", "dns")

        if packet.haslayer(scapy.Raw):
            try:
                payload = packet[scapy.Raw].load.decode(errors="ignore")
                if any(keyword in payload.lower() for keyword in ["user", "pass", "email"]):
                    self.log("❗ Possible Credentials: " + payload, "cred")
                if self.raw_var.get():
                    self.log("--- Raw Payload ---\n" + payload, "info")
            except:
                self.log("[x] Could not decode raw payload.", "cred")

        self.packet_count += 1
        self.update_status()

    def start_mitmproxy(self):
        try:
            if os.name == 'nt':
                subprocess.Popen(["mitmdump"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                subprocess.Popen(["mitmdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("[*] mitmproxy started for HTTPS interception.", "info")
        except Exception as e:
            self.log(f"[!] Could not start mitmproxy: {e}", "cred")

    def export_logs(self):
        export_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if export_file:
            with open(export_file, "w") as f:
                f.write("\n".join(self.log_lines))
            messagebox.showinfo("Export Complete", f"Logs saved to {export_file}")

    def on_close(self):
        try:
            self.log_file.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
