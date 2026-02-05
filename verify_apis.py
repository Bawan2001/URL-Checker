
import os
import requests
from dotenv import load_dotenv
from analyzer import WebScamAnalyzer

# Load environment variables
load_dotenv()

def test_apis():
    analyzer = WebScamAnalyzer()
    print("--- Testing API Configurations ---")
    
    # 1. Test RDAP Fallback (Simulate WHOIS failure)
    print("\n[1] Testing RDAP Fallback...")
    rdap_result = analyzer._get_rdap_fallback('google.com')
    if rdap_result:
        print("✅ RDAP Fallback Success:")
        print(f"   Registrar: {rdap_result.get('registrar')}")
        print(f"   Creation Date: {rdap_result.get('creation_date')}")
    else:
        print("❌ RDAP Fallback Failed")

    # 2. Test Google Safe Browsing
    print("\n[2] Testing Google Safe Browsing...")
    key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if key and not key.startswith('your_'):
        print(f"   Key found: {key[:5]}...")
        # Test with a known safe URL
        result = analyzer._check_google_safe_browsing('https://google.com')
        if 'error' in result:
             print(f"❌ GSB Failed: {result['error']}")
        elif result.get('threats_found', False):
             print("⚠️ GSB: Threats found (Unexpected for google.com)")
        else:
             print("✅ GSB Success: No threats found for google.com")
    else:
        print("⚠️ Google Safe Browsing Key not configured")

    # 3. Test AbuseIPDB
    print("\n[3] Testing AbuseIPDB...")
    key = os.getenv('ABUSEIPDB_API_KEY')
    if key and not key.startswith('your_'):
        print(f"   Key found: {key[:5]}...")
        # Test with a generic IP (Google DNS)
        result = analyzer._check_abuseipdb('8.8.8.8')
        if 'error' in result:
             print(f"❌ AbuseIPDB Failed: {result['error']}")
        else:
             print(f"✅ AbuseIPDB Success: Score {result.get('abuse_score')}")
    else:
        print("⚠️ AbuseIPDB Key not configured")

if __name__ == "__main__":
    test_apis()
