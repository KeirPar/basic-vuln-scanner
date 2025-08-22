import sys
import time

# Spinner function to show progress during scanning
def spinner_dots(target, ports, stop_event):
    while not stop_event.is_set():
        for i in range(4):
            if stop_event.is_set():  # Check again to exit quickly
                break
            sys.stdout.write(f"\rScanning {target} for ports: {ports if ports else '1-1024'} {'.'*i}{' '*(3-i)}")
            sys.stdout.flush()
            time.sleep(0.3)