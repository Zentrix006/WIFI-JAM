import subprocess
import os
import sys

BETTERCAP_PATH = 'bettercap' 
WIRESHARK_PATH = 'wireshark' 

def run_bettercap_module(interface, target_ip=None, module="http.proxy"):
    """
    Spawns a Bettercap process with a specific module enabled.
    """
    command = [
        BETTERCAP_PATH, 
        f'-iface {interface}', 
        f'-caplet {module}', 
        '--allow-external-ip'
    ]
    
    if target_ip:
        print(f"[!] Bettercap starting {module} targeting {target_ip}...")
    
    try:
        process = subprocess.Popen(
            ' '.join(command), 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid 
        )
        return {"status": "success", "pid": process.pid, "command": ' '.join(command)}
    except FileNotFoundError:
        return {"status": "error", "message": f"Bettercap not found. Ensure it is installed and in your PATH."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def open_wireshark_capture(interface, capture_filter=""):
    """
    Spawns a Wireshark GUI process to capture on the specified interface.
    """
    command = [
        WIRESHARK_PATH, 
        '-i', interface
    ]
    
    if capture_filter:
        command.extend(['-k', '-f', capture_filter])
        
    try:
        # Popen without blocking wait
        subprocess.Popen(command, close_fds=True) 
        return {"status": "success", "message": f"Wireshark opened on {interface} with filter: {capture_filter}"}
    except FileNotFoundError:
        return {"status": "error", "message": f"Wireshark not found. Ensure it is installed and in your PATH."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def stop_process(pid):
    """Gracefully terminates a process given its PID."""
    if pid is None:
        return {"status": "error", "message": "No process PID provided."}
    try:
        os.kill(pid, 15) 
        return {"status": "success", "message": f"Process {pid} terminated."}
    except ProcessLookupError:
        return {"status": "error", "message": f"Process {pid} not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

ACTIVE_BETTERCAP_PROCESSES = {}
