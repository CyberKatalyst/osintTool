# Import standard and third-party libraries for domain OSINT functionalities
import pyfiglet
import time
# Defining the white color and border style
WHITE = "\033[38;2;255;255;255m"
BORDER = "\033[1;97m" + "-" * 60 + "\033[0m"


def title():
    Title = pyfiglet.figlet_format("Domain OSINT")
    print(Title)
    time.sleep(2)

    print(f"{WHITE}🔍 DomInt - The Ultimate OSINT Tool for Domains \n{BORDER}")
    print(f"{WHITE}This tool will gather intelligence about a domain, including:")
    print(f"{WHITE}Registration status, IP data, DNS records, WHOIS info, subdomains, and more.")
    print(f"{WHITE}Just follow the steps and let DomInt do the work! 🚀 \n{BORDER}\n\n")

