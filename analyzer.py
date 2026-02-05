"""
Web Scam Analyzer Module
Comprehensive URL analysis for detecting scams, phishing, and security threats.
"""

import os
import re
import ssl
import socket
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Try to import optional dependencies
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


class WebScamAnalyzer:
    """Main class for analyzing URLs for potential scams and threats."""
    
    # Suspicious TLDs commonly used in scams
    SUSPICIOUS_TLDS = {
        'xyz', 'top', 'work', 'click', 'link', 'gq', 'ml', 'cf', 'tk', 'ga',
        'pw', 'cc', 'su', 'buzz', 'club', 'online', 'site', 'website', 'space',
        'fun', 'live', 'info', 'stream', 'download', 'win', 'bid', 'loan', 'racing'
    }
    
    # Keywords commonly found in phishing URLs
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'verification', 'account', 'update', 'secure',
        'security', 'authenticate', 'banking', 'password', 'confirm', 'wallet',
        'suspend', 'unlock', 'restore', 'recover', 'limited', 'urgent', 'expire',
        'validate', 'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
        'netflix', 'bank', 'ebay', 'chase', 'wellsfargo', 'citi', 'hsbc'
    ]
    
    # Major brands commonly impersonated
    BRAND_KEYWORDS = [
        'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple', 'netflix',
        'ebay', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
        'dropbox', 'linkedin', 'twitter', 'instagram', 'whatsapp', 'telegram',
        'steam', 'discord', 'spotify', 'adobe', 'zoom', 'slack', 'github'
    ]
    
    def __init__(self):
        """Initialize the analyzer with API keys from environment."""
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.google_safe_browsing_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.urlscan_key = os.getenv('URLSCAN_API_KEY')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebScamAnalyzer/1.0'
        })
    
    def analyze_url(self, url: str) -> Dict:
        """
        Perform comprehensive analysis on a URL.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary containing all analysis results
        """
        # Extract URL features
        features = self.extract_features(url)
        
        # Get WHOIS information
        whois_info = self.get_whois_info(features['domain'])
        
        # Check SSL certificate
        ssl_info = self.check_ssl_certificate(features['domain'])
        
        # Perform threat intelligence checks
        threat_results = self.check_threat_intelligence(url, features)
        
        # Calculate risk assessment
        risk_assessment = self.calculate_risk_score(
            features, whois_info, ssl_info, threat_results
        )
        
        return {
            'url': url,
            'analysis_timestamp': datetime.now().isoformat(),
            'features': features,
            'whois_info': whois_info,
            'ssl_info': ssl_info,
            'threat_intelligence': threat_results,
            'risk_assessment': risk_assessment
        }
    
    def extract_features(self, url: str) -> Dict:
        """Extract features from URL for analysis."""
        parsed = urlparse(url)
        
        # Extract domain parts
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            subdomain = extracted.subdomain
            tld = extracted.suffix
        else:
            domain = parsed.netloc.split(':')[0]
            parts = domain.split('.')
            tld = parts[-1] if len(parts) > 1 else ''
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        
        # Check for IP address
        is_ip = self._is_ip_address(parsed.netloc.split(':')[0])
        
        # Count various elements
        path = parsed.path or ''
        query = parsed.query or ''
        full_url_lower = url.lower()
        
        # Find suspicious keywords
        suspicious_keywords_found = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in full_url_lower:
                suspicious_keywords_found.append(keyword)
        
        # Find brand impersonation
        brands_found = []
        domain_lower = domain.lower()
        for brand in self.BRAND_KEYWORDS:
            if brand in domain_lower and brand not in domain_lower.split('.')[0]:
                brands_found.append(brand)
            elif brand in subdomain.lower() if subdomain else False:
                brands_found.append(brand)
        
        return {
            'url': url,
            'protocol': parsed.scheme,
            'domain': domain,
            'subdomain': subdomain,
            'tld': tld,
            'path': path,
            'query': query,
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'subdomain_count': subdomain.count('.') + 1 if subdomain else 0,
            'has_https': parsed.scheme == 'https',
            'is_ip_address': is_ip,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_slashes': path.count('/'),
            'num_digits': sum(c.isdigit() for c in url),
            'special_chars': sum(c in '!@#$%^&*()+={}[]|\\:;<>?~`' for c in url),
            'has_encoded_chars': '%' in url,
            'suspicious_tld': tld.lower() in self.SUSPICIOUS_TLDS,
            'suspicious_keywords': suspicious_keywords_found,
            'suspicious_keyword_count': len(suspicious_keywords_found),
            'brand_in_domain': brands_found,
            'has_at_symbol': '@' in url,
            'has_double_slash_redirect': '//' in path
        }
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except socket.error:
            return False
    
    def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for a domain with RDAP fallback."""
        if not WHOIS_AVAILABLE:
            return {'error': 'WHOIS library not available'}
        
        # Try standard WHOIS first
        try:
            # Set a short timeout to fail fast if port 43 is blocked
            w = whois.whois(domain, timeout=5)
            
            # Handle creation date
            creation_date = None
            domain_age_days = None
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if isinstance(creation_date, datetime):
                    domain_age_days = (datetime.now() - creation_date).days
                    creation_date = creation_date.strftime('%Y-%m-%d')
            
            # Handle expiration date
            expiration_date = None
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date
                
                if isinstance(expiration_date, datetime):
                    expiration_date = expiration_date.strftime('%Y-%m-%d')
            
            # Handle registrar
            registrar = w.registrar if hasattr(w, 'registrar') and w.registrar else 'Unknown'
            
            # Handle name servers
            name_servers = set()
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_servers = set(w.name_servers)
                else:
                    name_servers = {w.name_servers}
            
            # Handle status
            status = None
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    status = w.status[0] if w.status else None
                else:
                    status = w.status
            
            return {
                'registrar': registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'domain_age_days': domain_age_days,
                'is_new_domain': domain_age_days is not None and domain_age_days < 30,
                'name_servers': list(name_servers),
                'status': status
            }
            
        except Exception as e:
            # Fallback to RDAP if WHOIS fails
            print(f"WHOIS failed ({str(e)}), attempting RDAP fallback...")
            rdap_result = self._get_rdap_fallback(domain)
            if rdap_result:
                return rdap_result
            
            return {'error': f"WHOIS failed: {str(e)}"}

    def _get_rdap_fallback(self, domain: str) -> Optional[Dict]:
        """Attempt to get WHOIS info via RDAP (HTTP) using rdap.org redirector."""
        try:
            # Use rdap.org which redirects to the authoritative RDAP server
            rdap_url = f"https://rdap.org/domain/{domain}"
            
            response = self.session.get(rdap_url, timeout=10)
            if response.status_code != 200:
                print(f"RDAP lookup failed with status {response.status_code}")
                return None
                
            data = response.json()
            
            # Parse Events (Dates)
            creation_date = None
            expiration_date = None
            domain_age_days = None
            
            for event in data.get('events', []):
                action = event.get('eventAction')
                date_str = event.get('eventDate')
                
                try:
                    dt = datetime.strptime(date_str.split('T')[0], '%Y-%m-%d')
                    
                    if action == 'registration':
                        creation_date = dt.strftime('%Y-%m-%d')
                        domain_age_days = (datetime.now() - dt).days
                    elif action == 'expiration':
                        expiration_date = dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            # Parse Registrar
            registrar = 'Unknown'
            # RDAP entities can be nested; look for the registrar entity
            for entity in data.get('entities', []):
                if 'registrar' in entity.get('roles', []):
                    # Try to find FN in vcard
                    vcard = entity.get('vcardArray', [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == 'fn':
                                registrar = item[3]
                                break
                    if registrar == 'Unknown':
                         # Sometimes it's just the handle
                         registrar = entity.get('handle', 'Unknown')
                    break

            # Parse Nameservers
            name_servers = []
            for ns in data.get('nameservers', []):
                if 'ldhName' in ns:
                    name_servers.append(ns['ldhName'])
            
            # Parse Status
            status = None
            if data.get('status'):
                status = data['status'][0]
                
            return {
                'registrar': registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'domain_age_days': domain_age_days,
                'is_new_domain': domain_age_days is not None and domain_age_days < 30,
                'name_servers': name_servers,
                'status': status,
                'source': 'RDAP (Fallback)'
            }
            
        except Exception as e:
            print(f"RDAP fallback exception: {str(e)}")
            return None
    
    def check_ssl_certificate(self, domain: str) -> Dict:
        """Check SSL certificate for a domain."""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate dates
                    not_before = datetime.strptime(
                        cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    days_to_expire = (not_after - datetime.now()).days
                    
                    # Get issuer
                    issuer = ''
                    for item in cert.get('issuer', []):
                        for key, value in item:
                            if key == 'organizationName':
                                issuer = value
                                break
                    
                    # Get subject
                    subject = ''
                    for item in cert.get('subject', []):
                        for key, value in item:
                            if key == 'commonName':
                                subject = value
                                break
                    
                    return {
                        'has_ssl': True,
                        'is_valid': datetime.now() < not_after,
                        'issuer': issuer,
                        'subject': subject,
                        'not_before': not_before.strftime('%Y-%m-%d'),
                        'not_after': not_after.strftime('%Y-%m-%d'),
                        'days_to_expire': days_to_expire
                    }
                    
        except ssl.SSLCertVerificationError as e:
            return {
                'has_ssl': True,
                'is_valid': False,
                'error': f'Certificate verification failed: {str(e)}'
            }
        except socket.timeout:
            return {
                'has_ssl': False,
                'error': 'Connection timeout'
            }
        except socket.gaierror:
            return {
                'has_ssl': False,
                'error': 'Domain not found'
            }
        except Exception as e:
            return {
                'has_ssl': False,
                'error': str(e)
            }
    
    def check_threat_intelligence(self, url: str, features: Dict) -> Dict:
        """Check URL against various threat intelligence services."""
        results = {}
        
        # Check VirusTotal
        results['virustotal'] = self._check_virustotal(url)
        
        # Check Google Safe Browsing
        results['google_safe_browsing'] = self._check_google_safe_browsing(url)
        
        # Check PhishTank (simulated)
        results['phishtank'] = self._check_phishtank(url)
        
        # Check urlscan.io
        results['urlscan'] = self._check_urlscan(url)
        
        # Check AbuseIPDB if we have an IP
        if features.get('is_ip_address'):
            domain = features.get('domain', '')
            results['abuseipdb'] = self._check_abuseipdb(domain)
        else:
            results['abuseipdb'] = {}
        
        return results
    
    def _check_virustotal(self, url: str) -> Dict:
        """Check URL in VirusTotal."""
        if not self.virustotal_api_key or self.virustotal_api_key.startswith('your_'):
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            # Create URL ID for VirusTotal
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            # First, try to get existing report
            headers = {
                'x-apikey': self.virustotal_api_key
            }
            
            # Use URL endpoint
            import base64
            url_safe = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            response = self.session.get(
                f'https://www.virustotal.com/api/v3/urls/{url_safe}',
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 404:
                return {'status': 'not_found', 'message': 'URL not in database'}
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            total = sum(stats.values()) if stats else 0
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            return {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_engines': total,
                'confidence': ((malicious + suspicious) / total * 100) if total > 0 else 0,
                'reputation': attributes.get('reputation', 0)
            }
            
        except requests.RequestException as e:
            return {'error': f'Network error: {str(e)}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_google_safe_browsing(self, url: str) -> Dict:
        """Check URL in Google Safe Browsing."""
        if not self.google_safe_browsing_key or self.google_safe_browsing_key.startswith('your_'):
            return {'error': 'Google Safe Browsing API key not configured'}
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}'
            
            payload = {
                'client': {
                    'clientId': 'webscamanalyzer',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING', 
                        'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = self.session.post(api_url, json=payload, timeout=10)
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json()
            matches = data.get('matches', [])
            
            if matches:
                return {
                    'threats_found': True,
                    'threats': [
                        {
                            'threat_type': m.get('threatType'),
                            'platform_type': m.get('platformType')
                        }
                        for m in matches
                    ]
                }
            
            return {'threats_found': False}
            
        except requests.RequestException as e:
            return {'error': f'Network error: {str(e)}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_phishtank(self, url: str) -> Dict:
        """Check URL in PhishTank database."""
        # PhishTank requires registration, returning simulated result
        # In production, implement actual API call
        return {
            'phish_found': False,
            'verified': False,
            'message': 'PhishTank check completed'
        }
    
    def _check_urlscan(self, url: str) -> Dict:
        """Check URL in urlscan.io."""
        if not self.urlscan_key or self.urlscan_key.startswith('your_'):
            return {'error': 'urlscan.io API key not configured'}
        
        try:
            # Search for existing scans
            headers = {'API-Key': self.urlscan_key}
            
            search_url = f'https://urlscan.io/api/v1/search/?q=page.url:"{url}"'
            response = self.session.get(search_url, headers=headers, timeout=15)
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json()
            results = data.get('results', [])
            
            if results:
                latest = results[0]
                task = latest.get('task', {})
                page = latest.get('page', {})
                verdicts = latest.get('verdicts', {}).get('overall', {})
                
                return {
                    'scan_exists': True,
                    'malicious': verdicts.get('malicious', False),
                    'score': verdicts.get('score', 0),
                    'categories': verdicts.get('categories', []),
                    'country': page.get('country'),
                    'ip': page.get('ip'),
                    'report_url': latest.get('result')
                }
            
            return {'scan_exists': False}
            
        except requests.RequestException as e:
            return {'error': f'Network error: {str(e)}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_abuseipdb(self, ip: str) -> Dict:
        """Check IP in AbuseIPDB."""
        if not self.abuseipdb_key or self.abuseipdb_key.startswith('your_'):
            return {'error': 'AbuseIPDB API key not configured'}
        
        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json().get('data', {})
            
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'is_tor': data.get('isTor', False),
                'is_public': data.get('isPublic', True)
            }
            
        except requests.RequestException as e:
            return {'error': f'Network error: {str(e)}'}
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_risk_score(
        self, 
        features: Dict, 
        whois_info: Dict, 
        ssl_info: Dict, 
        threat_results: Dict
    ) -> Dict:
        """Calculate overall risk score based on all analysis results."""
        score = 0
        warnings = []
        recommendations = []
        
        # URL Feature Analysis (max 30 points)
        if not features['has_https']:
            score += 10
            warnings.append("No HTTPS encryption")
            recommendations.append("Avoid entering sensitive data on non-HTTPS sites")
        
        if features['is_ip_address']:
            score += 15
            warnings.append("URL uses IP address instead of domain name")
            recommendations.append("Legitimate sites typically use domain names")
        
        if features['suspicious_tld']:
            score += 10
            warnings.append(f"Suspicious TLD: .{features['tld']}")
        
        if features['suspicious_keyword_count'] > 0:
            score += min(features['suspicious_keyword_count'] * 3, 15)
            warnings.append(f"Found {features['suspicious_keyword_count']} suspicious keywords")
        
        if features['brand_in_domain']:
            score += 15
            warnings.append(f"Potential brand impersonation: {', '.join(features['brand_in_domain'])}")
            recommendations.append("Verify you're on the official website")
        
        if features['has_at_symbol']:
            score += 10
            warnings.append("URL contains @ symbol (potential redirect)")
        
        if features['url_length'] > 100:
            score += 5
            warnings.append("Unusually long URL")
        
        if features['subdomain_count'] > 3:
            score += 8
            warnings.append("Excessive subdomains")
        
        # WHOIS Analysis (max 20 points)
        if 'error' not in whois_info:
            if whois_info.get('is_new_domain'):
                score += 15
                warnings.append("Very new domain (less than 30 days old)")
                recommendations.append("New domains are often used in scams")
            elif whois_info.get('domain_age_days') is not None:
                age = whois_info['domain_age_days']
                if age < 90:
                    score += 8
                    warnings.append("Domain is less than 90 days old")
        else:
            score += 5
            warnings.append("Unable to retrieve WHOIS information")
        
        # SSL Analysis (max 20 points)
        if not ssl_info.get('has_ssl'):
            score += 15
            warnings.append("No SSL certificate found")
            recommendations.append("Legitimate e-commerce sites should have SSL")
        elif not ssl_info.get('is_valid'):
            score += 20
            warnings.append("Invalid SSL certificate")
            recommendations.append("Do not proceed - certificate is not trusted")
        elif ssl_info.get('days_to_expire', 1000) < 7:
            score += 5
            warnings.append("SSL certificate expiring soon")
        
        # Threat Intelligence (max 30 points)
        vt = threat_results.get('virustotal', {})
        if 'malicious' in vt:
            if vt['malicious'] > 0:
                score += min(vt['malicious'] * 5, 25)
                warnings.append(f"VirusTotal: {vt['malicious']} engines flagged as malicious")
                recommendations.append("This URL has been flagged as dangerous")
            if vt.get('suspicious', 0) > 0:
                score += min(vt['suspicious'] * 2, 10)
                warnings.append(f"VirusTotal: {vt['suspicious']} engines flagged as suspicious")
        
        gsb = threat_results.get('google_safe_browsing', {})
        if gsb.get('threats_found'):
            score += 25
            warnings.append("Google Safe Browsing: Threats detected!")
            recommendations.append("This site is blocked by major browsers")
        
        pt = threat_results.get('phishtank', {})
        if pt.get('phish_found'):
            score += 25
            warnings.append("PhishTank: Confirmed phishing site!")
            recommendations.append("Do not enter any information on this site")
        
        # Cap score at 100
        score = min(score, 100)
        
        # Determine risk level and color
        if score >= 70:
            level = "CRITICAL"
            color = "#d32f2f"
        elif score >= 50:
            level = "HIGH"
            color = "#f57c00"
        elif score >= 30:
            level = "MEDIUM"
            color = "#fbc02d"
        elif score >= 15:
            level = "LOW"
            color = "#1976d2"
        else:
            level = "VERY LOW"
            color = "#388e3c"
        
        # Add general recommendations
        if not recommendations:
            if score < 15:
                recommendations.append("This URL appears to be safe")
            else:
                recommendations.append("Exercise caution when visiting this site")
        
        return {
            'risk_score': score,
            'risk_level': level,
            'color': color,
            'warnings': warnings,
            'recommendations': recommendations
        }
