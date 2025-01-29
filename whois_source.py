# Import standard and third-party libraries for domain OSINT functionalities
import whois
import time
import sys
from tabulate import tabulate
import certificate
import domain_data
# Defining the white color and border style
WHITE = "\033[38;2;255;255;255m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"


def whois_search(domain):

    domain_name = domain
    whois_information = whois.whois(domain_name)

    extracted_data = []

    extracted_data.append(["Domain Name", whois_information.domain_name])
    extracted_data.append(["Domain Registrar", whois_information.registrar])
    extracted_data.append(["WHOIS Server", whois_information.whois_server])
    extracted_data.append(["Domain Creation Date", whois_information.creation_date])
    extracted_data.append(["Expiration Date", whois_information.expiration_date])
    extracted_data.append(["Updated Date", whois_information.updated_date])
    extracted_data.append(["Name Servers", whois_information.name_servers])
    extracted_data.append(["Status", whois_information.status])
    extracted_data.append(["Email Addresses", whois_information.emails])
    extracted_data.append(["Name", whois_information.name])
    extracted_data.append(["Organization", whois_information.org])
    extracted_data.append(["Address", whois_information.address])
    extracted_data.append(["City", whois_information.city])
    extracted_data.append(["State", whois_information.state])
    extracted_data.append(["Zipcode", whois_information.zipcode])
    extracted_data.append(["Country", whois_information.country])

    # Print the WHOIS information in tabular format
    print(tabulate(extracted_data, headers=["\033[1;95mField\033[0m", "\033[1;95mValue\033[0m"], tablefmt="fancy_grid"))
    print(f"{BORDER}")

    time.sleep(3)

    choice = input(f"\n{WHITE}➡️ Would you link to check the domain certificate? [y/n]: ").strip().lower()
    if choice == "y":
        print("✅ Extracting domain certificate information, please wait...")
        certificate.crt_sh(domain_name)
    if choice == "n":
        print(f"{WHITE}❌ Skipping the domain certificate information part. Moving to subdomain scanner ...")
        domain_data.subdomain_scanner(domain_name)
    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)
