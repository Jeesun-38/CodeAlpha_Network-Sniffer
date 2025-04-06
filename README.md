# 🛡️ Zetsu - Network Packet Sniffer

Zetsu Packet sniffer is a sleek, cross-platform packet sniffer built in Python with a modern GUI. It can capture and display HTTP, DNS, TCP, UDP, and partially intercept HTTPS traffic with mitmproxy integration. Tailored for analysts, developers, and cybersecurity enthusiasts.

---

## ✨ Features

- ✅ Live packet capture on selected network interfaces
- 🌐 Supports HTTP, DNS, TCP, UDP, and partial HTTPS sniffing
- 🔍 Real-time filtering by protocol or keyword
- 🔐 Mitmproxy integration for HTTPS interception
- 📄 Toggleable raw payload display
- 🧠 Auto-detects potential credentials in unencrypted traffic
- 📊 Live packet counter with GUI status bar
- 💾 Export captured logs to text files

---

## 🧪 Getting Started

 **Install requirements**


1. **Install mitmproxy** *(optional, for HTTPS sniffing)*:

```bash
pip install mitmproxy
```

2. **Run as admin/root** *(required for capturing network traffic)*:

```bash
sudo python zetsu.py
```

3. **(Optional) Trust the mitmproxy certificate** *(to inspect HTTPS traffic)*:

- Open a browser and go to `http://mitm.it` while mitmproxy is running.
- Download and trust the certificate appropriate for your OS/device.

---

## 📦 Protocol Support Matrix

Zetsu supports sniffing and logging across various network protocols. Here's a summary:

| Protocol      | Captured ✅ | Readable Data 📖 | Notes                                                                 |
|---------------|-------------|------------------|-----------------------------------------------------------------------|
| **HTTP**      | ✅ Yes      | ✅ Yes            | Full access: URLs, headers, payloads, potential credentials            |
| **HTTPS**     | ✅ Yes      | ❌ No by default  | Encrypted. Mitmproxy enables interception with cert injection         |
| **DNS**       | ✅ Yes      | ✅ Yes            | Extracts domain name queries                                          |
| **FTP**       | ✅ Yes      | ✅ Yes            | If unencrypted, usernames/passwords may be visible                    |
| **SMTP/POP3** | ✅ Yes      | ⚠️ Partial        | Only visible if server doesn't use encryption (many use SSL/TLS)      |
| **TCP**       | ✅ Yes      | ✅ Yes            | General packet info + destination ports + raw payload if available    |
| **UDP**       | ✅ Yes      | ✅ Yes            | Similar to TCP, best results with DNS or known protocols              |

> 🔐 **Tip:** For full HTTPS sniffing, trust the mitmproxy cert from `http://mitm.it`. [More info →](https://docs.mitmproxy.org/stable/concepts-certificates/)

---

## 📁 Logs & Exporting

Zetsu automatically saves session logs to a timestamped `.txt` file.
You can also manually export logs via the GUI with the "Export Logs" button.

---

## ⚙️ Tech Stack

- 🐍 Built using [Scapy](https://scapy.net) for packet manipulation
- 🌐 HTTPS proxying via [Mitmproxy](https://mitmproxy.org)
- 💻 GUI crafted with [Tkinter](https://wiki.python.org/moin/TkInter)

---

## 📜 License

MIT License. Contributions, forks, and suggestions welcome!
