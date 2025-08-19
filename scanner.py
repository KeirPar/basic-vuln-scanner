#!/usr/bin/env python3
import nmap
import argparse
import time
import sys
import threading


#Just for Aesthetic purposes
def spinner_dots(target,ports):
    nm = nmap.PortScanner()
    while not done:
        # Display a spinner with dots
        for i in range(4):
            sys.stdout.write(f"\rScanning {target} for ports: {ports if ports else '1-1024'} {'.'*i}{' '*(3-i)}")
            sys.stdout.flush()
            time.sleep(0.3)


#Main function to scan address(s) and port(s)
#Uses Nmap
def scan_target(target, ports):
    nm = nmap.PortScanner()
    try:
        timer = time.time()
        global done
        done = False
        t = threading.Thread(target=spinner_dots, args=(target, ports))
        t.start()
        nm.scan(hosts=target, ports=ports if ports else '1-1024', arguments='-sV -O')  #-sV is used to detect service versions and -O is for opperating system, there are other arguments you can use
        done = True
        t.join()
    except Exception as e:
        print(f"[-] Error: {e}")
        return
    
    for host in nm.all_hosts():
        print(f"\n\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state().capitalize()}")
        print(f"Scan completed in {time.time() - timer:.2f} seconds\n")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                if 'osmatch' in nm[host] and nm[host]['osmatch']:
                    opera = nm[host]['osmatch'][0]
                else:
                    print("OS detection not available (need admin privileges or more data).")
                print(f"  Port: {port}\tState: {service['state']}\tService: {service['name']} \t Opperating System: {opera['name']} Accuracy: {opera['accuracy']}%")  #added for OS detection
                #added for OS detection
        

# Main entry point for the scan function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Vulnerability Scanner (Port Scanner) using nmap")
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--ports", help="Ports to scan (e.g., 22,80,443 or 1-65535)", default=None)
    args = parser.parse_args()

    scan_target(args.target, args.ports)
