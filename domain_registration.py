# Import required libraries and custom modules
import re
import whois


# Check if a Domain is Registered
def is_registered(target):
    regex_for_domain = re.search(r"https?://([^/]+)", target)
    if regex_for_domain:
        domain_name = regex_for_domain.group(1)
    else:
        domain_name = target
    try:
        dm = whois.whois(domain_name)
    except whois.parser.PywhoisError:
        return False
    except Exception as e:
        print(f"Unexpected error checking {domain_name}: {e}")
        return False
    else:
        return bool(dm.domain_name)