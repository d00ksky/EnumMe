import os
import subprocess

# Update package lists
print("Updating package lists...")
subprocess.run(["sudo", "dnf", "check-update"])

# Install Python3 and pip if they aren't installed
if not os.system("python3 --version"):
    print("Python 3 is already installed.")
else:
    print("Python 3 could not be found. Installing...")
    subprocess.run(["sudo", "dnf", "install", "-y", "python3"])

if not os.system("pip3 --version"):
    print("pip3 is already installed.")
else:
    print("pip3 could not be found. Installing...")
    subprocess.run(["sudo", "dnf", "install", "-y", "python3-pip"])

# Install Python libraries
print("Installing necessary Python libraries...")
subprocess.run(["pip3", "install", "-r", "requirements.txt"])

# Install necessary tools
tools = [
    ("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("SubOver", "go install github.com/Ice3man543/SubOver@latest"),
    ("knockpy", "git clone https://github.com/guelfoweb/knock.git && cd knock && pip3 install -r requirements.txt && cd .."),
    ("subbrute", "pip3 install dnspython && git clone https://github.com/TheRook/subbrute.git"),
    ("dnsrecon", "pip3 install dnsrecon"),
    ("amass", "go install -v github.com/owasp-amass/amass/v3/...@master@latest"),
    ("sublist3r.py", "git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r && python3 -m pip install -r requirements.txt && cd .."),
    ("dnsdumpster", "git clone https://github.com/nmmapper/dnsdumpster.git && cd dnsdumpster && python3 -m pip install -r requirements.txt && cd ..")
]

for tool, command in tools:
    try:
        subprocess.run(["command", "-v", tool], check=True)
        print(f"{tool} is already installed.")
    except subprocess.CalledProcessError:
        print(f"{tool} could not be found. Installing...")
        subprocess.run(["bash", "-c", command], check=True)

print("Installation and setup completed successfully.")
