import subprocess, time

portlist = [22, 1080, 2745, 3127, 3389, 4444, 5554, 8866, 9898, 9988, 12345, 27374, 31337]
suspicious = {}
status = ""

while True:
    netstat = subprocess.check_output("netstat -ano", shell=True).decode()
    new_suspicious = {c.split()[1:3]: c for p in portlist for c in netstat.split("\n") if f":{p}" in c and "[" not in c}
    [subprocess.run(f"netsh advfirewall firewall add rule name=\"SUS CONNECTION: {ip},{port}\" protocol=TCP dir=inout localip={ip} remoteip={ip} localport={port} remoteport={port} action=block", shell=True) and print("\a") for (ip, port), c in new_suspicious.items() if (ip, port) not in suspicious]
    suspicious = new_suspicious
    new_status = "\n\033[1;31m  [+] Suspicious connections found:\033[0m" if suspicious else "\n\033[1;32m  [-] Connection Clean\033[0m"
    status_changed = new_status != status
    status = new_status
    print(new_status) if status_changed else None
    time.sleep(1)
