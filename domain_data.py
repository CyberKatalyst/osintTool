# Import standard and third-party libraries for domain OSINT functionalities
import socket
import requests
import sys
from tabulate import tabulate
import dns_info
import whois_source
import time
# Defining the white color and border style
WHITE = "\033[38;2;255;255;255m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"
GREEN = "\033[0;32m"
BOLD = "\033[1m"

# Retrieve Domain IP Address & Geolocation Data
def domain_ip(domain):
    try:
        domain_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Error: Unable to resolve {domain}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

    # Get IP Geolocation from ip-api.com - free version
    try:
        response = requests.get(f'http://ip-api.com/json/{domain_ip}')
        response.raise_for_status()
        ip_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP geolocation data: {e}")
        ip_data = {}

    # Get IP Data from ipinfo.io - free version
    try:
        response = requests.get(f'https://ipinfo.io/{domain_ip}/json')
        response.raise_for_status()
        ipinfo_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from IPinfo.io: {e}")
        ipinfo_data = {}

    # Combine data from both sources
    extracted_data = [
        ["IP Address", domain_ip],
        ["Organization", ipinfo_data.get("org", "N/A")],
        ["City", ip_data.get("city", "N/A")],
        ["Region", ip_data.get("regionName", "N/A")],
        ["Country", ip_data.get("country", "N/A")],
        ["Postal Code", ipinfo_data.get("postal", "N/A")],
        ["Location (Lat, Lon)", ipinfo_data.get("loc", "N/A")],
        ["Timezone", ip_data.get("timezone", "N/A")],
    ]

    # Print the data in a table format
    print(tabulate(extracted_data, headers=["\033[1;95mField\033[0m", "\033[1;95mValue\033[0m"], tablefmt="fancy_grid"), f"\n{BORDER}")

    while True:
        choice = input(
            f"\n{WHITE}➡️ Would you like to extract DNS records? [y/n]: ").strip().lower()
        if choice == "y":
            print(f"{WHITE}✅ Extracting DNS records, please wait...")
            dns_info.dns_records(domain)
            break
        if choice == "n":
            print(f"{WHITE}❌ Skipping the DNS records part. Moving to whois search function ...")
            whois_source.whois_search()
            break
        else:
            print(f"{WHITE}❗Invalid input. Please enter 'y' for Yes or 'n' for No.")
            sys.exit(1)


# WebOSINT Subscan (Subdomain Scanner)
def subdomain_scanner(domain_name):
    subdomains_found = []
    sdsreq = requests.get(f'https://crt.sh/?q={domain_name}&output=json')

    # Check if the request was successful
    if sdsreq.status_code == 200:
        print("✅ Extracting subdomains information, please wait...\n")
    else:
        print(f"{WHITE}The subdomain scanner tool is currently offline.")
        sys.exit(1)

    # Extract subdomains from the response
    for (key, value) in enumerate(sdsreq.json()):
        subdomains_found.append(value['name_value'])

    # Sort and remove duplicates
    subdomains = sorted(set(subdomains_found))

    # Prepare data for tabulate
    extracted_data = []
    if subdomains:
        for sub_link in subdomains:
            extracted_data.append([sub_link])  # Add subdomains to the table
    else:
        print(f"{WHITE}No subdomains found for {domain_name}")
        extracted_data.append(["No subdomains found"])

    # Print the subdomains in a table format
    print(tabulate(extracted_data, headers=["Subdomains Found"], tablefmt="fancy_grid"))

    # Print scan completion message
    print(f"{WHITE}Subdomain Scan Completed! {GREEN}{BOLD}- ALL Subdomains have been Found \n{BORDER}\n")

    # Prompt for saving the results
    time.sleep(3)
    choice = input(f"{WHITE}Would you like to save all results in PDF file? [y/n]: ").strip().lower()
    if choice == "y":
        file_name = input("Enter the file name: ")
        # You can implement the logic to save the results as PDF here
        print(f"Saving results to {file_name}.pdf")
    elif choice == "n":
        print(f"\n\n{WHITE}The Domain Recon is completed!")
        sys.exit(1)
    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)




