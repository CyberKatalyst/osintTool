# Import standard and third-party libraries for domain OSINT functionalities
import certificate
import whois
import sys
import domain_data
import domain_registration
import dns_info
import menu


def print_section_border():
    print("\033[1;35m" + "-" * 60 + "\033[0m")


PURPLE = "\033[38;2;147;112;219m"
WHITE = "\033[38;2;255;255;255m"
RESET = "\033[0m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"

menu.title()

# Section 1: Domain Input
query = input(f"\n{PURPLE}🌐 Enter Domain/URL: {RESET}").strip()
domain = query

# Searching for domain registration
print(f"\n{BORDER} \n{WHITE}🔍 Searching for domain registration: {domain}... 🔄{RESET}")
# Check if domain is registered
if domain_registration.is_registered(domain):
    print(f"{WHITE}✅ The domain '{domain}' is registered.\n{BORDER}\n")
else:
    print(f"{WHITE}❌ The domain '{domain}' is not registered.\n{BORDER}\n")


while True:
    choice = input(f"""{WHITE}➡️ Would you like to retrieve domain IP address & geolocation data? [y/n]: """).strip().lower()
    if choice == "y":
        print(f"{WHITE}🔍 Extracting IP address & geolocation data  ... 🔄{RESET}")
        domain_data.domain_ip(query)
        break
    elif choice == "n":
        print("\033[1;93m\n❌ Skipping domain IP retrieval. Moving to DNS records...\033[0m")
        dns_info.dns_records(query)
        break
    else:
        print("\033[1;91m\n❗ Invalid input. Please enter 'y' for Yes or 'n' for No.\033[0m")
        sys.exit(1)


def main():
    domain_registration.is_registered()
    domain_data.domain_ip(query)
    dns_info.dns_records()
    whois.whois_search()
    certificate.crt_sh()
    domain_data.domain_reputation()
    domain_data.subdomain_scanner()
    whois.whois_history()


if __name__ == '__main__':
    main()