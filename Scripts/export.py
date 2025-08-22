import json
import csv
from datetime import datetime
import os

#ASKING TO EXPORT RESULTS
def export_scan_results(nm, target, scan_time):
   # Ask user if they want to export results
    export_choice = input("\n[?] Would you like to export these scan results? (y/n): ").lower().strip()
    
    if export_choice not in ['y', 'yes']:
        return
    
    print("\nAvailable export formats:")
    print("1. JSON")
    print("2. CSV") 
    print("3. TXT (Human readable)")
    
    format_choice = input("Choose format (1-3): ").strip()
    
    # Create filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"scan_{target.replace('/', '_')}_{timestamp}"
    
    # Create exports directory if it doesn't exist
    if not os.path.exists('exports'):
        os.makedirs('exports')
    
    try:
        if format_choice == "1":
            export_to_json(nm, target, scan_time, base_filename)
        elif format_choice == "2":
            export_to_csv(nm, target, scan_time, base_filename)
        elif format_choice == "3":
            export_to_txt(nm, target, scan_time, base_filename)
        else:
            print(" Invalid choice, export cancelled")
    except Exception as e:
        print(f" Export failed: {e}")


#JSON
def export_to_json(nm, target, scan_time, base_filename):
    filename = f"exports/{base_filename}.json"
    scan_data = {
        "scan_info": {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "duration": scan_time,
            "scanner": "Basic Vulnerability Scanner"
        },
        "hosts": []
    }
    
    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "ports": []
        }
        
        # Add OS information if available
        try:
            if nm[host].get('osmatch') and len(nm[host]['osmatch']) > 0:
                host_data["os"] = {
                    "name": nm[host]['osmatch'][0]['name'],
                    "accuracy": nm[host]['osmatch'][0]['accuracy']
                }
        except:
            pass
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                port_data = {
                    "port": port,
                    "protocol": proto,
                    "state": service['state'],
                    "service": service['name'],
                    "version": service.get('version', ''),
                    "product": service.get('product', ''),
                    "scripts": service.get('script', {})
                }
                host_data["ports"].append(port_data)
        
        scan_data["hosts"].append(host_data)
    
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=2)
    
    print(f" Exported to JSON: {filename}")

#CSV
def export_to_csv(nm, target, scan_time, base_filename):
    filename = f"exports/{base_filename}.csv"
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Hostname', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Product']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    writer.writerow({
                        'IP': host,
                        'Hostname': nm[host].hostname(),
                        'Port': port,
                        'Protocol': proto,
                        'State': service['state'],
                        'Service': service['name'],
                        'Version': service.get('version', ''),
                        'Product': service.get('product', '')
                    })
    
    print(f"Exported to CSV: {filename}")

#BASIC TXT FILE
def export_to_txt(nm, target, scan_time, base_filename):
    filename = f"exports/{base_filename}.txt"
    
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("VULNERABILITY SCAN REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan Duration: {scan_time:.2f} seconds\n")
        f.write("=" * 60 + "\n\n")
        
        for host in nm.all_hosts():
            f.write(f"Host: {host} ({nm[host].hostname()})\n")
            f.write(f"State: {nm[host].state()}\n")
            
            # OS Information (if available)
            try:
                if nm[host].get('osmatch') and len(nm[host]['osmatch']) > 0:
                    f.write(f"OS: {nm[host]['osmatch'][0]['name']} (Accuracy: {nm[host]['osmatch'][0]['accuracy']}%)\n")
            except:
                f.write("OS: Unable to determine\n")
            
            f.write("-" * 40 + "\n")
            f.write("OPEN PORTS:\n")
            f.write("-" * 40 + "\n")
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    f.write(f"Port: {port}/{proto}\n")
                    f.write(f"  State: {service['state']}\n")
                    f.write(f"  Service: {service['name']}\n")
                    #Check to see if version or product information is available
                    if service.get('version'):
                        f.write(f"  Version: {service['version']}\n")
                    if service.get('product'):
                        f.write(f"  Product: {service['product']}\n")
                    
                    # Script results
                    if service.get('script'):
                        f.write("  Script Results:\n")
                        for script_name, script_output in service['script'].items():
                            f.write(f"    {script_name}:\n")
                            for line in script_output.split('\n')[:3]:  # First 3 lines
                                if line.strip():
                                    f.write(f"      {line.strip()}\n")
                    f.write("\n")
            
            f.write("\n" + "=" * 60 + "\n\n")
    
    print(f"Exported to TXT: {filename}")
