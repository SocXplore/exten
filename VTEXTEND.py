import os
import zipfile
import hashlib
import requests
import time

API_KEY = "APIkey"

def zip_extension(extension_path, zip_name):
    """Compresses the Chrome extension folder into a zip."""
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for foldername, _, filenames in os.walk(extension_path):
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                zipf.write(filepath, os.path.relpath(filepath, extension_path))
    return zip_name

def get_sha256(file_path):
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def upload_to_virustotal(file_path):
    """Uploads file to VirusTotal and returns the analysis ID."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(url, headers=headers, files=files)
    return response.json()

def get_analysis_result(analysis_id):
    """Polls VirusTotal for scan results until completed."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    while True:
        response = requests.get(url, headers=headers)
        data = response.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data
        time.sleep(3)

def scan_all_extensions():
    """Scans all installed Chrome extensions."""
    base_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions")
    if not os.path.exists(base_path):
        print("[!] Chrome extensions folder not found.")
        return

    for ext_id in os.listdir(base_path):
        ext_path = os.path.join(base_path, ext_id)
        for version_folder in os.listdir(ext_path):
            full_path = os.path.join(ext_path, version_folder)
            if os.path.isdir(full_path):
                zip_name = f"{ext_id}.zip"
                zip_extension(full_path, zip_name)
                sha256 = get_sha256(zip_name)
                print(f"\n[+] Scanning Extension ID: {ext_id}")
                print(f"    → SHA256: {sha256}")
                try:
                    upload_response = upload_to_virustotal(zip_name)
                    analysis_id = upload_response["data"]["id"]
                    result = get_analysis_result(analysis_id)
                    stats = result["data"]["attributes"]["stats"]
                    if stats["malicious"] > 0:
                        print("    [!] Malicious extension detected.")
                    else:
                        print("    [✓] Clean.")
                except Exception as e:
                    print(f"    [!] Error scanning extension: {e}")
                os.remove(zip_name)

if __name__ == "__main__":
    print("[*] Starting Chrome Extension Scan...")
    scan_all_extensions()
