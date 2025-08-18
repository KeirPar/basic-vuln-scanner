#!/usr/bin/env python3
import nmap
import argparse

def scan_target(target, ports):
    nm = nmap.PortScanner()
    print(f"[+] Scanning {target} for ports: {ports if ports else '1-1024'}")

    try:
        nm.scan(hosts=target, ports=ports if ports else '1-1024', arguments='-sV')
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                print(f"  Port: {port}\tState: {service['state']}\tService: {service['name']} {service.get('version', '')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Vulnerability Scanner (Port Scanner)")
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--ports", help="Ports to scan (e.g., 22,80,443 or 1-65535)", default=None)
    args = parser.parse_args()

    scan_target(args.target, args.ports)
