import requests
import socket
from urllib.parse import urljoin
import argparse
from termcolor import colored


WORDLIST_PATH = './dir.txt'

def get_ip_address(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(colored(f"Error resolving IP for {url}: {e}", 'red'))
        return None

def categorize_status_code(status_code):
    if 100 <= status_code < 200:
        return 'Informational'
    elif 200 <= status_code < 300:
        return 'Success'
    elif 300 <= status_code < 400:
        return 'Redirection'
    elif 400 <= status_code < 500:
        return 'Client Error'
    elif 500 <= status_code < 600:
        return 'Server Error'
    else:
        return 'Unknown'

def scan_directory(url, status_codes):
    found = []
    with open(WORDLIST_PATH, 'r') as f:
        paths = f.readlines()

    print(colored(f"Scanning URL: {url}", 'cyan'))
    print(colored("Status Code | IP Address      | URL                                           | Category", 'yellow'))

    for path in paths:
        path = path.strip()
        if not path.startswith('/'):
            path = '/' + path
        test_url = urljoin(url, path)
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=True)
            final_url = response.url
            status_code = response.status_code
            ip_address = get_ip_address(final_url)
            status_category = categorize_status_code(status_code)
            
            status_code_str = f"{status_code}".ljust(12)
            ip_address_str = f"{ip_address}" if ip_address else "N/A"
            ip_address_str = ip_address_str.ljust(15)
            url_str = f"{test_url}".ljust(45)
            

            if str(status_code) in status_codes:
                if status_code == 200:
                    print(colored(f"{status_code_str} | {ip_address_str} | {url_str} | {status_category}", 'green'))
                    if final_url != test_url:
                        print(colored(f"    from: {test_url}", 'blue'))
                        print(colored(f"    to:   {final_url}", 'blue'))
                    found.append(test_url)
                else:
                    color = 'red' if status_code >= 400 else 'yellow'
                    print(colored(f"{status_code_str} | {ip_address_str} | {url_str} | {status_category}", color))
            
        except requests.RequestException as e:
            print(colored(f"Error with {test_url}: {e}", 'red'))
    
    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Directory scanner')
    parser.add_argument('url', type=str, help='The target URL (e.g., http://example.com)')
    parser.add_argument('--status', type=str, default='200,301,302,403,404,500', 
                        help='Comma-separated list of status codes to display (e.g., 200,404,500)')
    
    args = parser.parse_args()
    

    status_codes = set(args.status.split(','))
    
    found_directories = scan_directory(args.url, status_codes)
    
    if found_directories:
        print(colored("Directories found:", 'cyan'))
        for directory in found_directories:
            print(colored(directory, 'green'))
    else:
        print(colored("No directories found.", 'red'))
