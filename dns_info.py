# Import standard and third-party libraries for domain OSINT functionalities
import requests
import sys
import whois_source
from tabulate import tabulate
# Defining the white color and border style
WHITE = "\033[38;2;255;255;255m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"


# Search DNS Records
def dns_records(domain):
    # API URL for DNS lookup
    dnsrecords_api = "https://api.hackertarget.com/dnslookup/"
    dns_records = {"q": domain}

    # Sending the request to the API
    response = requests.get(dnsrecords_api, params=dns_records)

    # Splitting the response into lines
    records = response.text.splitlines()

    extracted_data = []

    # Loop through each record and extract type and value
    for record in records:
        record_type, value = record.split(": ")

        # Adding the record and its explanation
        extracted_data.append([f"{record_type}", value])

    # Print the formatted table using tabulate
    print(tabulate(extracted_data, headers=["\033[1;95mField\033[0m", "\033[1;95mValue\033[0m"], tablefmt="fancy_grid"), f"\n{BORDER}")

    choice = input(f"\n{WHITE}➡️ Would you like to process with a Whois scan? y/n: \033[0m").strip().lower()
    if choice == "y":
        print("✅ Extracting Whois scan results, please wait...")
        whois_source.whois_search(domain)
    if choice == "n":
        sys.exit(1)
    else:
        print("You pressed the wrong key; choose Y or N, please start again")
        sys.exit(1)
