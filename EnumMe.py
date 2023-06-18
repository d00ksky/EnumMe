import os
import subprocess
import requests
import time
import argparse
import logging
import concurrent.futures
import json
import shutil
from fake_useragent import UserAgent
from stem import Signal
from stem.control import Controller
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from threading import BoundedSemaphore
import validators
import sublist3r


class Recon:
    def __init__(self, domains, use_proxies=False, mode='normal', delay=30, concurrent_domains=1, verbose=False, use_ct=True, output_dir="", use_subbrute=False, wordlist=None, test_mode=False):
        self.domains = domains
        self.use_proxies = use_proxies
        self.mode = mode
        self.delay = delay
        self.concurrent_domains = concurrent_domains
        self.output_dir = output_dir if output_dir else None
        self.ct_api_url = "https://crt.sh/?q=%.{domain}&output=json"
        self.unique_subdomains = set()
        self.alive_subdomains = set()
        self.logger = self.setup_logger(verbose)
        self.use_ct = use_ct
        self.use_subbrute = use_subbrute
        self.wordlist = wordlist
        self.test_mode = test_mode

        # Initialize a UserAgent object for generating random user agents
        self.user_agent = UserAgent()

        # Set up a session for making requests
        self.session = requests.Session()

        # Set up a Retry object to handle retries
        self.retry = Retry(
            total=5,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        # Set up a HTTPAdapter with our Retry object
        self.adapter = HTTPAdapter(max_retries=self.retry)

        # Attach the HTTPAdapter to our session
        self.session.mount("https://", self.adapter)
        self.session.mount("http://", self.adapter)

        if self.use_proxies:
            self.proxies = {
                "http": "socks5://127.0.0.1:9050",
                "https": "socks5://127.0.0.1:9050",
            }

        # Semaphore to limit the number of concurrent requests
        self.semaphore = BoundedSemaphore(self.concurrent_domains)

        # Set the base directory where the script is located
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        # Set the paths for the tools
        self.tool_paths = {
            'SubOver': os.path.join(self.base_dir, 'SubOver'),
            'subfinder': os.path.join(self.base_dir, 'subfinder'),
            'knockpy': os.path.join(self.base_dir, 'knockpy'),
            'dnsrecon': os.path.join(self.base_dir, 'dnsrecon'),
            'amass': os.path.join(self.base_dir, 'amass'),
            'dnsdumpster': os.path.join(self.base_dir, 'dnsdumpster', 'dnsdumpster.py'),
            'sublist3r': os.path.join(self.base_dir, 'sublist3r', 'sublist3r.py')
        }

        # Semaphore to limit the number of concurrent requests
        self.semaphore = BoundedSemaphore(self.concurrent_domains)

    def setup_logger(self, verbose):
        logger = logging.getLogger('recon')
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # File Handler
        file_handler = logging.FileHandler('recon.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO if verbose else logging.WARNING)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def run(self):
        if self.test_mode:
            self.test_tool_availability()
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent_domains) as executor:
                futures = [executor.submit(self.enum_domain, domain) for domain in self.domains]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Error in enumerating subdomains: {str(e)}")

        self.save_unique_subdomains()
        self.save_alive_subdomains()


    def test_tool_availability(self):
        tools = [
            'SubOver',
            'subfinder',
            'knockpy',
            'dnsrecon',
            'amass',
            'dnsdumpster',
            'sublist3r'
        ]
        for tool in tools:
            try:
                self.logger.info(f"Testing availability of {tool}")
                subprocess.run(tool, shell=True, capture_output=True, text=True, timeout=10, check=True)
                self.logger.info(f"{tool} is available.")
            except FileNotFoundError:
                self.logger.error(f"{tool} is not available.")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error in running {tool}: {str(e)}")
            except subprocess.TimeoutExpired:
                self.logger.error(f"{tool} execution timed out.")

    def enum_domain(self, domain):
        try:
            self.create_output_dir(domain)
            self.logger.info("Enumerating subdomains for domain: {}".format(domain))

            if self.mode == 'normal' and self.use_ct:
                try:
                    self.unique_subdomains.update(self.ct_query(domain))
                except Exception as e:
                    self.logger.error(f"Error in CT scan for {domain}: {str(e)}")

            try:
                if self.use_subbrute:
                    self.subbrute_scan(domain)
                self.dnsrecon_scan(domain)
                self.amass_scan(domain)
                self.run_dnsdumpster(domain)

                if not self.unique_subdomains:
                    self.sublist3r_scan(domain)
                    self.subover_scan(domain)
                    self.subfinder_scan(domain)
                    self.knockpy_scan(domain)
            except Exception as e:
                self.logger.error(f"Error in subdomain enumeration for {domain}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error in enumerating subdomains for {domain}: {str(e)}")

    def create_output_dir(self, domain):
        dir_name = f"recon_{domain}"
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        self.output_dir = os.path.abspath(dir_name)


    def ct_query(self, domain):
        with self.semaphore:
            self.logger.info(f"Running CT scan for {domain}")
            subdomains = []
            url = self.ct_api_url.format(domain=domain)
            try:
                headers = {'User-Agent': self.user_agent.random}
                response = self.session.get(url, headers=headers, proxies=self.proxies if self.use_proxies else None)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        subdomain = entry['name_value']
                        subdomains.append(subdomain)
                        self.logger.info(f"Found subdomain via CT: {subdomain}")
            except Exception as e:
                raise RuntimeError(f"Error in CT scan for {domain}: {str(e)}")
            return subdomains

    def save_unique_subdomains(self):
        file_path = os.path.join(self.output_dir, "unique_subdomains.txt")
        with open(file_path, "w") as file:
            file.write("\n".join(self.unique_subdomains))

        self.logger.info(f"Saved unique subdomains to: {file_path}")

    def save_alive_subdomains(self):
        file_path = os.path.join(self.output_dir, "alive_subdomains.txt")
        with open(file_path, "w") as file:
            file.write("\n".join(self.alive_subdomains))

        self.logger.info(f"Saved alive subdomains to: {file_path}")

    def save_alive_links(self):
        all_links = []

        for domain in self.unique_subdomains:
            if self.is_alive(domain):
                all_links.append(domain)

        file_path = os.path.join(self.output_dir, "alive_links.txt")
        with open(file_path, "w") as file:
            file.write("\n".join(all_links))

        self.logger.info(f"Saved alive links to: {file_path}")

    def is_alive(self, target):
        try:
            response = requests.get(target)
            if response.status_code == 200:
                self.logger.info(f'Target {target} is reachable.')
                return True
            else:
                self.logger.info(f'Target {target} is not reachable.')
        except requests.exceptions.RequestException as e:
            self.logger.info(str(e))
        return False

    def run_sublist3r(self, domain, threads=30, savefile=None, verbose=False):
        cmd = ['python', 'Sublist3r/sublist3r.py', '-d', domain, '-o', f'{self.output_dir}/sublist3r.txt']

        if threads:
            cmd.extend(['-t', str(threads)])
        if savefile:
            cmd.extend(['-o', savefile])
        if verbose:
            cmd.append('-v')

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error in running Sublist3r for {domain}: {str(e)}")

    def sublist3r_scan(self, domain):
        self.logger.info(f"Running Sublist3r scan for {domain}")
        savefile = f"{self.output_dir}/sublist3r.txt"
        self.run_sublist3r(domain, threads=30, savefile=savefile, verbose=False)

        if os.path.isfile(savefile):
            with open(savefile, 'r') as file:
                subdomains = file.read().splitlines()

            for subdomain in subdomains:
                self.logger.info(f"Found subdomain via Sublist3r: {subdomain}")
        else:
            self.logger.info(f"No subdomains found via Sublist3r for {domain}")

    def subover_scan(self, domain):
        self.logger.info(f"Running SubOver scan for {domain}")
        # Write the domain to a file
        with open(f"{self.output_dir}/subdomains.txt", "a") as file:
            file.write(domain + "\n")

        cmd = ['SubOver', '-l', f'{self.output_dir}/subdomains.txt', '-o', f'{self.output_dir}/subover.txt']
        self.run_cmd(cmd, domain, tool_name="SubOver")

    def subfinder_scan(self, domain):
        self.logger.info(f"Running Subfinder scan for {domain}")
        cmd = ['subfinder', '-d', domain, '-o', f'{self.output_dir}/subfinder.txt']
        self.run_cmd(cmd, domain, tool_name="subfinder")

    def knockpy_scan(self, domain):
        self.logger.info(f"Running Knockpy scan for {domain}")
        cmd = ['knockpy', domain, '-o', f'{self.output_dir}/knockpy.txt']
        self.run_cmd(cmd, domain, tool_name="knockpy")

    def subbrute_scan(self, domain):
        current_dir = os.getcwd()
        os.chdir('./subbrute/')
        self.logger.info(f"Running Subbrute scan for {domain}")
        cmd = ['python3', 'subbrute.py', domain, '-o', f'../{self.output_dir}/subbrute.txt']
        self.run_cmd(cmd, domain, tool_name="Subbrute")
        os.chdir(current_dir)

    def dnsrecon_scan(self, domain):
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.logger.info(f"Running DNSRecon scan for {domain}")
        if self.wordlist:
            cmd = ['dnsrecon', '-d', domain, '-D', self.wordlist, '-x', f'{self.output_dir}/dnsrecon.xml']
        else:
            cmd = ['dnsrecon', '-d', domain, '-D', 'Seclists_Discovery_DNS.txt', '-x', f'{self.output_dir}/dnsrecon.xml']
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"Scan for {domain} completed successfully: {' '.join(cmd)}")
            self.logger.debug(f"Standard Output:\n{process.stdout}")
            self.logger.debug(f"Standard Error:\n{process.stderr}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error in scan for {domain} using DNSRecon: {str(e)}")
            self.logger.error(f"Standard Output:\n{e.stdout}")
            self.logger.error(f"Standard Error:\n{e.stderr}")
        except Exception as e:
            self.logger.error(f"Unexpected error in scan for {domain} using DNSRecon: {str(e)}")


    def amass_scan(self, domain):
        self.logger.info(f"Running Amass scan for {domain}")
        cmd = ['amass', 'enum', '-d', domain, '-o', f'{self.output_dir}/amass.txt']
        self.run_cmd(cmd, domain, tool_name="Amass")


    def run_dnsdumpster(self, domain):
            self.logger.info(f"Running DNSDumpster for {domain}")
            cmd = ['python', self.tool_paths['dnsdumpster'], '-d', domain]

            try:
                process = subprocess.run(cmd, capture_output=True, text=True, check=True)
                output = process.stdout.strip()
                self.parse_dnsdumpster_output(output, domain)
                self.logger.info(f"DNSDumpster scan for {domain} completed successfully")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error in DNSDumpster scan for {domain}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Unexpected error in DNSDumpster scan for {domain}: {str(e)}")


    def parse_dnsdumpster_output(self, output, domain):
        try:
            data = json.loads(output)
            for entry in data:
                subdomain = entry.get("subdomain")
                if subdomain:
                    self.logger.info(f"Found subdomain via DNSDumpster: {subdomain}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Error in parsing DNSDumpster output for {domain}: {str(e)}")




    def run_cmd(self, cmd, domain, tool_name):
        try:
            self.logger.info(f"Running {' '.join(cmd)} for {domain}")
            output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.logger.info(f"Scan for {domain} using {tool_name} completed successfully: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error in scan for {domain} using {tool_name}: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in scan for {domain} using {tool_name}: {' '.join(cmd)} -> {str(e)}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument('-d', '--domains', nargs='+', help="Domains to scan")
    parser.add_argument('-f', '--file', type=str, help="File containing domains to scan")
    parser.add_argument('-p', '--proxies', action='store_true', help="Use proxies for scanning")
    parser.add_argument('-m', '--mode', choices=['normal', 'advanced'], default='normal', help="Scanning mode (default: normal)")
    parser.add_argument('--delay', type=int, default=30, help="Delay between requests in seconds (default: 30)")
    parser.add_argument('-c', '--concurrent', type=int, default=1, help="Number of concurrent domain scans (default: 1)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Increase output verbosity")
    parser.add_argument('--ct', action='store_true', help="Use certificate transparency for enumeration")
    parser.add_argument('--output_dir', type=str, default="", help="Output directory for scan results")
    parser.add_argument('--subbrute', action='store_true', help="Enable Subbrute scan")
    parser.add_argument('-w', '--wordlist', type=str, default=None, help="Custom wordlist file for scanning")
    parser.add_argument('--test', action='store_true', help="Test mode to check tool availability")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    if args.test:
        recon = Recon(domains=[], test_mode=True)
        recon.run()
    else:
        if args.domains is None and args.file is None:
            print("Error: You must provide either domains or a file.")
            exit(1)

        domains = []
        if args.domains:
            for domain in args.domains:
                if validators.domain(domain):
                    domains.append(domain)
                else:
                    print(f"Invalid domain: {domain}")

        if args.file:
            if os.path.isfile(args.file):
                with open(args.file, "r") as file:
                    for line in file:
                        domain = line.strip()
                        if validators.domain(domain):
                            domains.append(domain)
                        else:
                            print(f"Invalid domain in file: {domain}")

        if len(domains) == 0:
            print("Error: No valid domains provided.")
            exit(1)

        recon = Recon(
            domains=domains,
            use_proxies=args.proxies,
            mode=args.mode,
            delay=args.delay,
            concurrent_domains=args.concurrent,
            verbose=args.verbose,
            use_ct=args.ct,
            output_dir=args.output_dir,
            use_subbrute=args.subbrute,
            wordlist=args.wordlist
        )

        recon.run()