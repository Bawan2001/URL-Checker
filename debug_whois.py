import whois
import sys

print(f"python-whois imported from: {whois.__file__}")

try:
    domain = "google.com"
    print(f"Attempting to query WHOIS for {domain}...")
    w = whois.whois(domain)
    print("WHOIS Success!")
    print(w)
except Exception as e:
    print(f"WHOIS Failed: {e}")
    import traceback
    traceback.print_exc()
