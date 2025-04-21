## 🛡️ Zetsu - Network Packet Sniffer

Zetsu - Network Packet Sniffer is a sleek, cross-platform (Linux & Mac) packet sniffer built in Python with a modern GUI. It can capture and display HTTP, DNS, TCP, and UDP, and even attempt to decrypt HTTPS traffic with mitmproxy integration. Tailored for analysts, developers, and cybersecurity enthusiasts.

---

## ✨ Features

- ✅ Live packet capture on selected network interfaces
- 🌐 Supports HTTP, DNS, TCP, UDP, and partial HTTPS sniffing
- 🔍 Real-time filtering by protocol or keyword
- 🔐 Mitmproxy integration for HTTPS interception
- 📄 Raw payload view toggle
- 🧠 Credential detection from unencrypted traffic
- 📊 Live packet counter + status bar
- 📂 Export logs to text files

---

## 🧪 How to Use

1. **Clone the repository**

```bash
git clone https://github.com/Jeesun-38/CodeAlpha_Network-Sniffer.git && cd CodeAlpha_Network-Sniffer

```

2. **Install dependencies**

```bash
pip install scapy psutil mitmproxy
```

3. **Run as admin/root** (required for interface sniffing):

```bash
sudo python sniffer.py / sudo python3 sniffer.py
```

4. **Trust the mitmproxy cert** (for HTTPS decryption):

- Visit `http://mitm.it` while mitmproxy is running.
- Download and trust the certificate for your OS/device.

---

## 📦 Supported Protocols

Here's what **Zetsu-Network Packet Sniffer** can detect and display during a packet sniffing session:

| Protocol     | Captured ✅ | Readable Data 📖 | Notes |
|--------------|-------------|------------------|-------|
| **HTTP**     | ✅ Yes      | ✅ Yes            | Full visibility: URLs, headers, payloads, potential credentials |
| **HTTPS**    | ✅ Yes      | ⚠️ Partial        | Encrypted by default — Mitmproxy can help intercept plaintext via certificate injection |
| **DNS**      | ✅ Yes      | ✅ Yes            | Domain names and queries are visible |
| **FTP**      | ✅ Yes      | ✅ Yes            | If unencrypted, can expose usernames and passwords |
| **SMTP/POP3**| ✅ Yes      | ⚠️ Partial        | Cleartext data only if SSL/TLS is not used (most servers use encryption now) |
| **TCP**      | ✅ Yes      | ✅ Yes            | Generic transport layer analysis — can show destination ports and raw data |
| **UDP**      | ✅ Yes      | ✅ Yes            | Limited visibility unless it's a known protocol like DNS |

> 🔐 **Tip:** For full HTTPS inspection, install and trust the Mitmproxy certificate on your system. [Learn more →](https://docs.mitmproxy.org/stable/concepts-certificates/)

---

## 💡 Notes

- You must run with elevated privileges to capture packets.
- HTTPS interception only works if the mitmproxy certificate is trusted.

---

## 📁 Log Files

It saves each session's log to a timestamped `.txt` file automatically.
You can also manually export logs using the GUI.

---

## 🙌 Credits

- 🐍 Built with [Scapy](https://scapy.net)
- 🌐 HTTPS proxy via [Mitmproxy](https://mitmproxy.org)
- 💻 GUI using [Tkinter](https://wiki.python.org/moin/TkInter)

---

## 📜 License

MIT License. Feel free to fork, contribute, or customize!
