#!/usr/bin/env python3
import nmap
import argparse
import sys
import time
import threading

from spinner import spinner_dots #importing the spinner function


#Main function to scan address(s) and port(s)
#Uses Nmap
def scan_target(target, ports):
    nm = nmap.PortScanner()
    try:
        timer = time.time()
        stop_event = threading.Event()
        t = threading.Thread(target=spinner_dots, args=(target, ports, stop_event))
        t.start()


        #NOTE: USING -O CAN CAUSE ISSUES WITH SOME SYSTEMS, I HAVE IT REMOVED BECAUSE TO SCAN METASPLOITABLE 2, IT WOULD NOT WORK
        #ADD -O IF YOU WANT TO TRY TO GET OS INFORMATION
       
       #for --scripts, we are only checking for a few common vulnerabilities due to how long it takes to run a full vulnerability scan (vuln)
        nm.scan(hosts=target, ports=ports if ports else '1-1024', arguments=' -Pn -sT -sV --script ftp-vsftpd-backdoor,ssh-hostkey,http-title,smb-os-discovery')

        stop_event.set()  # Signal the spinner to stop
        t.join()
    except Exception as e:
        print(f"Error: {e}")
        return
    


    for host in nm.all_hosts():
        print(f"\n\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state().capitalize()}")
        print(f"Scan completed in {time.time() - timer:.2f} seconds\n")
        #check to see if we were able to get OS information
        if( 'osmatch' in nm[host]):
            print(f"OS: {nm[host]['osmatch'][0]['name']} \t Accuracy: {nm[host]['osmatch'][0]['accuracy']}% \n")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto} \n" )
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                print(f"  Port: {port}\tState: {service['state']} \t Service: {service['name']} ")  

                if 'script' in service: # Check if there are any scripts run
                    print(f"    Vulnerability scan results:")
                    for script_name, script_output in service['script'].items():
                        print(f"      - {script_name}:")
                    # Format the output nicely
                        for line in script_output.split('\n'):
                            if line.strip():
                                print(f"        {line.strip()}")
            
        

# Main entry point for the scan function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Vulnerability Scanner (Port Scanner) using nmap")
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--ports", help="Ports to scan (e.g., 22,80,443 or 1-65535)", default=None)
    args = parser.parse_args()

    scan_target(args.target, args.ports)
