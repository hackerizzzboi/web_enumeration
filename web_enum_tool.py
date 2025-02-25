import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, filedialog
import socket
import whois
import requests
import ssl

def get_subdomains(domain):
    common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test']
    subdomains_found = []
    for sub in common_subdomains:
        try:
            subdomain = f"{sub}.{domain}"
            socket.gethostbyname(subdomain)
            subdomains_found.append(subdomain)
        except socket.gaierror:
            pass
    return subdomains_found

class WebEnumerationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Web Enumeration Tool")
        self.root.geometry("700x650")
        self.root.configure(bg="#e3f2fd")

        self.header_label = tk.Label(self.root, text="Web Enumeration Tool", font=("Arial", 16, "bold"), bg="#1565c0", fg="white", pady=10)
        self.header_label.pack(fill=tk.X)

        self.domain_frame = tk.Frame(self.root, bg="#e3f2fd")
        self.domain_frame.pack(pady=15)

        self.domain_label = tk.Label(self.domain_frame, text="Enter Domain Name:", font=("Arial", 12), bg="#e3f2fd")
        self.domain_label.pack(side=tk.LEFT, padx=10)

        self.domain_entry = tk.Entry(self.domain_frame, width=35, font=("Arial", 12), bd=2, relief=tk.GROOVE)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

        self.button_frame = tk.Frame(self.root, bg="#e3f2fd")
        self.button_frame.pack(pady=10)

        self.create_buttons()

        self.output_text = scrolledtext.ScrolledText(self.root, height=18, width=75, wrap=tk.WORD, font=("Arial", 11), bd=2, relief=tk.GROOVE)
        self.output_text.pack(pady=15, padx=10)
        
        self.save_button = None

    def create_buttons(self):
        buttons = [
            ("DNS Lookup", self.dns_lookup, "#4CAF50"),
            ("WHOIS Lookup", self.whois_lookup, "#FF9800"),
            ("HTTP Headers", self.http_headers, "#1976D2"),
            ("Port Scanner", self.port_scanner, "#673AB7"),
            ("Find Subdomains", self.find_subdomains, "#009688"),
            ("SSL Certificate", self.ssl_certificate, "#D84315"),
        ]
        for text, command, color in buttons:
            button = tk.Button(self.button_frame, text=text, command=command, font=("Arial", 10, "bold"), bg=color, fg="white", padx=10, pady=5, relief=tk.RAISED, bd=3)
            button.pack(side=tk.LEFT, padx=5, pady=5)

    def display_output(self, message):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, message + "\n")
        self.show_save_button()

    def show_save_button(self):
        if not self.save_button:
            self.save_button = tk.Button(self.root, text="Save Data", command=self.save_output, font=("Arial", 10, "bold"), bg="#F44336", fg="white", padx=10, pady=5, relief=tk.RAISED, bd=3)
            self.save_button.pack(pady=5)

    def save_output(self):
        # Open the file dialog for saving the file
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.output_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "Results saved successfully!")

    def dns_lookup(self):
        domain = self.domain_entry.get()
        if domain:
            try:
                ip_address = socket.gethostbyname(domain)
                self.display_output(f"DNS Lookup (IP Address): {ip_address}")
            except socket.gaierror:
                self.display_output("DNS Lookup failed. Invalid domain or no connection.")
        else:
            messagebox.showwarning("Input Error", "Please enter a domain name.")

    def whois_lookup(self):
        domain = self.domain_entry.get()
        if domain:
            try:
                domain_info = whois.whois(domain)  # Use the dynamic domain from user input
                self.display_output(f"WHOIS Lookup Results:\n{domain_info}")
            except Exception as e:
                self.display_output(f"WHOIS Lookup failed: {e}")
        else:
            messagebox.showwarning("Input Error", "Please enter a domain name.")


    def http_headers(self):
        domain = self.domain_entry.get()
        if domain:
            try:
                response = requests.head(f"http://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
                self.display_output(f"HTTP Headers:\n{response.headers}")
            except requests.exceptions.RequestException as e:
                self.display_output(f"HTTP Headers lookup failed: {e}")
        else:
            messagebox.showwarning("Input Error", "Please enter a domain name.")

    def port_scanner(self):
        domain = self.domain_entry.get()
        if domain:
            try:
                ip = socket.gethostbyname(domain)
                specific_ports = [
                    21,   # FTP
                    22,   # SSH
                    25,   # SMTP
                    53,   # DNS
                    80,   # HTTP
                    110,  # POP3
                    143,  # IMAP
                    443,  # HTTPS
                    3306, # MySQL
                    3389, # RDP
                    8080, # HTTP Proxy
                    8443, # HTTPS alternative
                    5900, # VNC
                    636,  # LDAPS
                    993,  # IMAPS
                    995,  # POP3S
                ]  
                open_ports = []
                for port in specific_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                self.display_output(f"Open Ports: {open_ports if open_ports else 'None found'}")
            except Exception as e:
                self.display_output(f"Port scanning failed: {e}")
        else:
            messagebox.showwarning("Input Error", "Please enter a domain name.")

    def find_subdomains(self):
        domain = self.domain_entry.get()
        if domain:
            subdomains = get_subdomains(domain)
            self.display_output(f"Subdomains Found: {', '.join(subdomains) if subdomains else 'None'}")
        else:
            messagebox.showwarning("Input Error", "Please enter a domain name.")

    def ssl_certificate(self):
        domain = self.domain_entry.get()
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                self.display_output(f"SSL Certificate:\n{cert}")
        except Exception as e:
            self.display_output(f"SSL Certificate fetch failed: {e}")

root = tk.Tk()
app = WebEnumerationTool(root)
root.mainloop()
