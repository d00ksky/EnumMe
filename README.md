# EnumMe

This is a Python script that performs subdomain enumeration for given domains. 
It utilizes various tools and techniques to discover subdomains.
This isn't finished project so I will be happy to hear feedback and try to
work on this and solve issues when I will have time.

## Requirements

- Python 3.x
- fake-useragent
- stem
- requests
- sublist3r

You also need to install 

- dnsdumpster
- sub0ver
- subfinder
- amass
- knockpy
- sublist3r
- subbrute

And be able to launch them by command or have them in folders in 
the same directory as this tool.

There is install script but it is not finished 
and you could have still something missing after launching it.

You can install the required dependencies using the following command:

```bash
pip install -r requirements.txt

Usage

To run the script, use the following command:

bash

python script.py [options]

Options

    -d, --domains: Domains to scan.
    -f, --file: File containing domains to scan.
    -p, --proxies: Use proxies for scanning.
    -m, --mode: Scanning mode (normal or advanced).
    --delay: Delay between requests in seconds (default: 30).
    -c, --concurrent: Number of concurrent domain scans (default: 1).
    -v, --verbose: Increase output verbosity.
    --ct: Use certificate transparency for enumeration.
    --output_dir: Output directory for scan results.
    --subbrute: Enable Subbrute scan.
    -w, --wordlist: Custom wordlist file for scanning.
    --test: Test mode to check tool availability.

Make sure to provide valid domains either through the -d option or by specifying a file using the -f option.
License

This project is licensed under the MIT License.
