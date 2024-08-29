import dns.resolver
import sys
import requests

def read_subdomains(filename):
    try:
        with open(filename, 'r') as file:
            subdomain_list = [line.strip() for line in file]
        return subdomain_list
    except FileNotFoundError:
        print(f"File {filename} tidak ditemukan.")
        sys.exit(1)


def check_active(subdomain):
    try:
        response = requests.get(f'http://{subdomain}', timeout=5)
        return response.status_code
    except requests.RequestException as e:
        return None


def display_dns_records(subdomain):
    try:
        a_records = dns.resolver.resolve(subdomain, 'A')
        ip_addresses = [record.to_text() for record in a_records]
        return ip_addresses
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        print(f"DNS Exception occurred: {e}")
        return []


def main():
    if len(sys.argv) != 3:
        print('Syntax Error - python3 subdomenum.py <domain> <subdomain_file>')
        sys.exit(1)

    domain = sys.argv[1]
    subdomain_file = sys.argv[2]
    subdomain_array = read_subdomains(subdomain_file)

    print(f"Scanning domain: {domain}\n")
    print(f"{'Subdomain':<30} {'Status':<10} {'Response Code':<15} {'IP Address'}")
    print("="*60)

    for subdoms in subdomain_array:
        full_subdomain = f'{subdoms}.{domain}'
        status_code = check_active(full_subdomain)
        if status_code:
            ip_addresses = display_dns_records(full_subdomain)
            ip_list = ', '.join(ip_addresses) if ip_addresses else 'No IP address found'
            print(f'{full_subdomain:<30} {"Active":<10} {status_code:<15} {ip_list}')
        else:
            print(f'{full_subdomain:<30} {"Inactive":<10} {"N/A":<15}')

if __name__ == "__main__":
    main()
