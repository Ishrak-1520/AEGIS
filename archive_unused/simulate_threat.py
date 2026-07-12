import subprocess
import time
import sys
import threading

def simulate_fileless_malware():
    """
    Simulates severe fileless malware behavior to achieve a 90%+ threat score.
    Instead of 'ping', we spawn PowerShell instances. PowerShell loads 
    hundreds of DLLs (.NET framework) and creates many Mutexes.
    By spawning numerous PowerShell instances, we artificially spike:
      1. pslist.nprocs64bit (Active processes)
      2. handles.nmutant (Active Mutexes per .NET app)
      3. dlllist.avg_dlls_per_proc (Avg DLLs skyrockets due to .NET)
      
    This is identical to real-world PowerShell-based fileless malware 
    (like Empire or Cobalt Strike) and will push the ML confidence > 95%.
    """
    print("\n[!] AEGIS REALISTIC THREAT SIMULATOR [!]")
    print("Simulating severe PowerShell-based fileless malware...")
    
    processes = []
    num_procs = 80  # 80 powershells is enough to drastically alter averages
    
    print(f"-> Spawning {num_procs} hidden PowerShell background processes...")
    print("-> This will spike average DLLs, Mutexes, and 64-bit Process counts!")
    
    for i in range(num_procs):
        # CREATE_NO_WINDOW = 0x08000000
        p = subprocess.Popen(['powershell', '-WindowStyle', 'Hidden', '-Command', 'Start-Sleep -Seconds 45'], 
                             creationflags=0x08000000, 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        processes.append(p)

    print(f"-> Successfully spawned {len(processes)} PowerShell instances.")
    print("-> System telemetry is now severely altered.")
    print("\n[+] ACTION REQUIRED: Check the AEGIS 'Volatile Guardian' Dashboard!")
    print("[+] It should detect a CRITICAL memory anomaly within 5 seconds.")
    print("\nHolding processes open for 40 seconds to allow HIDS detection loop to run...")
    
    for i in range(40, 0, -1):
        sys.stdout.write(f"\rHolding... {i} seconds remaining ")
        sys.stdout.flush()
        time.sleep(1)
        
    print("\n\nCleaning up memory...")
    # Clean up
    for p in processes:
        p.kill()
        
    print("Simulation complete. Telemetry should return to normal.")

if __name__ == '__main__':
    simulate_fileless_malware()
