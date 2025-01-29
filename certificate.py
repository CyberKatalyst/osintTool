# Import standard and third-party libraries for domain OSINT functionalities
import re
import requests
import json
from dateutil.parser import parse
import domain_data
import time
import sys
from tabulate import tabulate
# Defining the white color and border style
WHITE = "\033[38;2;255;255;255m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"


def crt_sh(domain_name):
    c = MyCrtsh()
    certs = c.search(domain_name)

    # Prepare data for tabulate
    extracted_data = []

    # If there are results, process them and display the first 6
    for cert in certs[:6]:
        # Extracting relevant information (assuming cert contains these fields)
        cert_info = [
            cert.get("name_value", "N/A"),  # Common Name or Domain
            cert.get("issuer", "N/A"),  # Issuer
            cert.get("not_before", "N/A"),  # Start Date
            cert.get("not_after", "N/A"),  # Expiration Date
            cert.get("serial_number", "N/A")  # Serial Number
        ]
        extracted_data.append(cert_info)

    # Print the results in a table format
    if extracted_data:
        print(tabulate(extracted_data,
                       headers=["Domain Name", "Issuer", "Start Date", "Expiration Date", "Serial Number"],
                       tablefmt="fancy_grid"))
    else:
        print(f"\n{WHITE}No certificates found for {domain_name}.")

    print(f"{BORDER}")

    # Asking user if they want to extract subdomains data
    time.sleep(3)
    choice = input(f"\n{WHITE}➡️ Would you like to extract subdomains data? [y/n]: ").strip().lower()

    if choice == "y":
        domain_data.subdomain_scanner(domain_name)
    elif choice == "n":
        print(f"\n\n\n{WHITE}The Domain Recon is completed!")
        sys.exit(1)
    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)


class MyCrtsh:
    def search(self, query, timeout=None):
        """
        Search crt.sh with the give query
        Query can be domain, sha1, sha256...
        """
        r = requests.get('https://crt.sh/', params={'q': query, 'output': 'json'}, timeout=timeout)
        nameparser = re.compile("([a-zA-Z]+)=(\"[^\"]+\"|[^,]+)")
        certs = []
        try:
            for c in r.json():
                if not c['entry_timestamp']:
                    continue
                certs.append({
                    'id': c['id'],
                    'logged_at': parse(c['entry_timestamp']),
                    'not_before': parse(c['not_before']),
                    'not_after': parse(c['not_after']),
                    'name': c['name_value'],
                    'ca': {
                        'caid': c['issuer_ca_id'],
                        'name': c['issuer_name'],
                        'parsed_name': dict(nameparser.findall(c['issuer_name']))
                    }
                })
        except json.decoder.JSONDecodeError:
            pass
        return certs
