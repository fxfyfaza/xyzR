import dns.resolver
import requests
import socket
import os
from urllib.parse import urljoin
from termcolor import colored

# Function to read subdomains from a file
def read_subdomains(filename): #Read list subdomain from file text
    if not filename.endswith('.txt'):
        filename += '.txt'
    try:
        with open(filename, 'r') as file:
            subdomain_list = [line.strip() for line in file]
        return subdomain_list
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []
#Function to Save active subdomains after scanning
def save_active_subdomains(active_subdomains, filename):
    try:
        with open(filename, 'w') as file:
            for subdomain in active_subdomains:
                file.write(subdomain + '\n')
        print(f"Active subdomains saved to {filename}")
    except Exception as e:
        print(f"An error occurred while saving to {filename}: {e}")

# Function to check if a subdomain is active and get the HTTP status code
def check_active(subdomain): #Checks if a subdomain is active by sending an HTTP request
    try:
        response = requests.get(f'http://{subdomain}', timeout=5)
        return response.status_code
    except requests.RequestException:
        return None

# Function to display DNS records
def display_dns_records(subdomain): #Displays DNS A records (IP adrdresses) for a given subdomain
    try:
        a_records = dns.resolver.resolve(subdomain, 'A')
        ip_addresses = [record.to_text() for record in a_records]
        return ip_addresses
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        print(f"DNS Exception occurred: {e}")
        return []

# Function to scan directories
def scan_directory(url, status_codes): #Scans directories on the given URL based on list of paths from a wordlist file
    found = []
    WORDLIST_PATH = './dir.txt'
    try:
        with open(WORDLIST_PATH, 'r') as f:
            paths = f.readlines()
    except FileNotFoundError:
        print(f"Wordlist {WORDLIST_PATH} not found.")
        return found

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

def get_ip_address(url): #Retrieves the IP address of a URL by resolving the hostname
    try:
        hostname = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(colored(f"Error resolving IP for {url}: {e}", 'red'))
        return None

def categorize_status_code(status_code): #Categories HTTP status code into categories (Informational, Success, Redirection, ClientError, ServerError)
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

# Function to generate dorks
def generate_dorks(domain): #Generates a set of dork queries for given domain
    dorks = {
        "PHP extension with parameters": f"site:{domain} ext:php inurl:? ",
        "API Endpoints": f"site:{domain} inurl:api | site:{domain} /rest | site:{domain} /v1 | site:{domain} /v2 | site:{domain} /v3",
        "Juicy Extensions": f"site:{domain} ext:log | ext:txt | ext:conf | ext:cnf | ext:env | ext:bak | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json",
        "High G inurl keywords": f"inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:admin | inurl:php site:{domain}",
        "Server Errors": f'inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace" site:{domain}',
        "XSS prone parameters": f'inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:{domain}',
        "Open Redirect prone parameters": f'inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:r2= | inurl:r3= inurl:& site:{domain}',
        "SQLi Prone Parameters": f'inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:{domain}',
        "SSRF Prone Parameters": f'inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:domain= | inurl:page= inurl:& site:{domain}',
        "LFI Prone Parameters": f'inurl:include= | inurl:dir= | inurl:detail= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:{domain}',
        "RCE Prone Parameters": f'inurl:cmd= | inurl:exec= | inurl:query= | inurl:keyword= | inurl:lang= | inurl:run= | inurl:ping= inurl:& site:{domain}',
        "FILE Upload endpoints": f'site:{domain} "choose file"',
        "API Docs": f'inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:{domain}',
        "Login Pages": f'inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:{domain}',
        "Test Environments": f'inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:{domain}',
        "Sensitive Documents": f'site:{domain} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute”',
        "Sensitive Parameters": f'inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:{domain}',
        "Adobe Experience Manager": f'inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:{domain}',
        "Disclosed XSS and Open Redirects": f'site:openbugbounty.org inurl:reports intext:{domain}',
        "Google Groups": f'site:groups.google.com "{domain}"',
        "Code Leaks": f'site:pastebin.com "{domain}" | site:jsfiddle.net "{domain}" | site:codebeautify.org "{domain}" | site:codepen.io "{domain}"',
        "Cloud Storage": f'site:s3.amazonaws.com "{domain}" | site:blob.core.windows.net "{domain}" | site:googleapis.com "{domain}" | site:drive.google.com "{domain}" | site:dev.azure.com "{domain}" | site:onedrive.live.com "{domain}" | site:digitaloceanspaces.com "{domain}" | site:sharepoint.com "{domain}" | site:s3-external-1.amazonaws.com "{domain}" | site:s3.dualstack.us-east-1.amazonaws.com "{domain}" | site:dropbox.com/s "{domain}" | site:box.com/s "{domain}" | site:docs.google.com inurl:"/d/" "{domain}"',
        "JFrog Artifactory": f'site:jfrog.io "{domain}"',
        "Firebase": f'site:firebaseio.com "{domain}" | site:*/security.txt "bounty"',
    }
    return dorks

# Function to display dorks
def display_dorks(dorks): #Displays the generated dork queries in a readable format
    for category, dork in dorks.items():
        print(colored(f"{category}:", 'cyan'))
        print(colored(f"    {dork}", 'green'))

def save_to_file(dorks, filename): #Saves the dork queries to a text file
    with open(filename, 'w') as file:
        for category, query in dorks.items():
            file.write(f"{category}:\n{query}\n\n")
    print(f"Dorks saved to {filename}")


# Main menu
def main_menu(): #Display the main menu with options for
    while True:
        print(r"""

                               /$$$$$$$ 
                              | $$__  $$
 /$$   /$$ /$$   /$$ /$$$$$$$$| $$  \ $$
|  $$ /$$/| $$  | $$|____ /$$/| $$$$$$$/
 \  $$$$/ | $$  | $$   /$$$$/ | $$__  $$
  >$$  $$ | $$  | $$  /$$__/  | $$  \ $$
 /$$/\  $$|  $$$$$$$ /$$$$$$$$| $$  | $$
|__/  \__/ \____  $$|________/|__/  |__/
           /$$  | $$                    
          |  $$$$$$/                    
           \______/    
                                  

""")
        print("[1]. Subdomain Scanning")
        print("[2]. Directory Scanning")
        print("[3]. Google Dork Generator")
        print("[0]. Exit")
        choice = input("Select: ").strip()

        if choice == '1':
            print(r"""

                               /$$$$$$$ 
                              | $$__  $$
 /$$   /$$ /$$   /$$ /$$$$$$$$| $$  \ $$
|  $$ /$$/| $$  | $$|____ /$$/| $$$$$$$/
 \  $$$$/ | $$  | $$   /$$$$/ | $$__  $$
  >$$  $$ | $$  | $$  /$$__/  | $$  \ $$
 /$$/\  $$|  $$$$$$$ /$$$$$$$$| $$  | $$
|__/  \__/ \____  $$|________/|__/  |__/
           /$$  | $$                    
          |  $$$$$$/                    
           \______/    
                                  

            """)
            domain = input("Enter domain (e.g., example.com): ").strip()
            filename = input("Enter range of Scanning files (100/500/1000/10000): ").strip()
            subdomains = read_subdomains(filename)
            active_subdomains = []
            if subdomains:
                for subdomain in subdomains:
                    full_domain = f"{subdomain}.{domain}"
                    print(f"\nChecking {full_domain}...")
                    ip_addresses = display_dns_records(full_domain)
                    if ip_addresses:
                        print(f"DNS Records for {full_domain}: {', '.join(ip_addresses)}")
                    status_code = check_active(full_domain) 
                    if status_code:
                        print(f"Subdomain {full_domain} is active with status code: {status_code}")
                        active_subdomains.append(full_domain)
                    else:
                        print(f"Subdomain {full_domain} is not active or inaccessible.")
                save_choice = input("Do you want to save active subdomains to a file? (y/n): ").strip().lower()
                if save_choice == 'y':
                    save_filename = input("Enter filename to save active subdomains (e.g., active_subdomains.txt): ").strip()
                    save_active_subdomains(active_subdomains, save_filename)
        elif choice == '2':
            print(r"""

                               /$$$$$$$ 
                              | $$__  $$
 /$$   /$$ /$$   /$$ /$$$$$$$$| $$  \ $$
|  $$ /$$/| $$  | $$|____ /$$/| $$$$$$$/
 \  $$$$/ | $$  | $$   /$$$$/ | $$__  $$
  >$$  $$ | $$  | $$  /$$__/  | $$  \ $$
 /$$/\  $$|  $$$$$$$ /$$$$$$$$| $$  | $$
|__/  \__/ \____  $$|________/|__/  |__/
           /$$  | $$                    
          |  $$$$$$/                    
           \______/    
                                  

""")
            url = input("Enter URL (e.g., http://example.com): ").strip()
            status_codes = input("Enter status codes to search for (comma-separated, e.g., 200,404): ").strip().split(',')
            status_codes = [code.strip() for code in status_codes]
            found_paths = scan_directory(url, status_codes)
            if found_paths:
                print("\nDirectories found:")
                for path in found_paths:
                    print(path)
            else:
                print("No directories found.")
        elif choice == '3':
            print(r"""

                               /$$$$$$$ 
                              | $$__  $$
 /$$   /$$ /$$   /$$ /$$$$$$$$| $$  \ $$
|  $$ /$$/| $$  | $$|____ /$$/| $$$$$$$/
 \  $$$$/ | $$  | $$   /$$$$/ | $$__  $$
  >$$  $$ | $$  | $$  /$$__/  | $$  \ $$
 /$$/\  $$|  $$$$$$$ /$$$$$$$$| $$  | $$
|__/  \__/ \____  $$|________/|__/  |__/
           /$$  | $$                    
          |  $$$$$$/                    
           \______/     
                                  

""")
            domain = input("Enter domain (e.g., example.com): ").strip()
            dorks = generate_dorks(domain)
            display_dorks(dorks)

            save_option = input("Do you want to save these dorks to a text file? (y/n): ").lower()
            if save_option in ["yes", "y"]:
                filename = input("Enter the filename (with .txt extension): ")
                save_to_file(dorks, filename)
            else:
                print("Dorks not saved.")
        elif choice == '0':
            print("Exiting the program...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__": #Ensures that `main_menu()` runs only if the script is executed directly, not if it is imported as a module
    main_menu()
