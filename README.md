# 🛡️ ChromeExtension-VTScanner

## Overview

**ChromeExtension-VTScanner** is a Python-based malware detection tool that scans all locally installed Google Chrome extensions. It compresses each extension, calculates its SHA256 hash, and submits it to the [VirusTotal](https://www.virustotal.com) API to identify any malicious components.

This project is ideal for cybersecurity students, blue team analysts, or anyone interested in browser hygiene and extension threat detection.

---

## Features

- 🔍 **Automatic Chrome Extension Scanning**: Detects all installed Chrome extensions from the default directory.
- 🧱 **ZIP Compression + SHA256 Hashing**: Each extension is zipped and hashed before submission.
- ☁️ **VirusTotal API Integration**: Automatically uploads zipped files and fetches scan results.
- 📊 **Real-time Threat Detection**: Clearly flags malicious extensions using VT’s threat intelligence.
- 🧹 **Temporary File Cleanup**: Deletes zip files after scanning to save storage.

---

## 💻 How to Use

### 1. Replace the API Key

Edit `vtf.py` and insert your VirusTotal API key:

```python
API_KEY = "virustotal_api_key"
Get your key here: https://www.virustotal.com/gui/user/apikey

2. Run the Script

python3 vtf.py

Expected output:

[*] Starting Chrome Extension Scan...

[+] Scanning Extension ID: abcdefg1234567
    → SHA256: 1234abcd5678efgh...
    [✓] Clean.

[+] Scanning Extension ID: malicious9876
    [!] Malicious extension detected.

```
### 📂 Chrome Extension Location
The script automatically scans this folder:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions
Each extension’s version folder is compressed and analyzed.
```
### 🧰 Requirements

Python 3.x
requests module

Install dependencies with:
```
pip install requests
```
### 🧪 Example
```
python3 vtf.py
```
### Sample run:
```
[*] Starting Chrome Extension Scan...

[+] Scanning Extension ID: abc123
    → SHA256: 0f4d99eabc...
    [✓] Clean.

[+] Scanning Extension ID: ext999
    [!] Malicious extension detected.
```
### 🔧 Input Parameters
No input is needed during runtime — the tool automatically:

Scans installed extensions

Compresses them

Hashes them

Uploads to VirusTotal

Shows results in real-time

### 📚 Use Cases
🧑‍🎓 Cybersecurity academic and mini projects

🛡️ SOC analysis and malware detection

🔍 Forensic investigation on browsers

🔬 Chrome extension integrity verification
