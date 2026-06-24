import re
from urllib.parse import urlparse

# List of common URL shortening services
SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly', 'is.gd', 'buff.ly', 
    'adf.ly', 'bit.do', 'ow.ly', 'goo.gl', 'shorte.st', 'tiny.cc'
}

# Suspicious words often found in phishing URLs
SUSPICIOUS_WORDS = [
    'login', 'signin', 'bank', 'secure', 'paypal', 'ebay', 'amazon', 
    'update', 'verify', 'webscr', 'free', 'gift', 'card', 'bonus', 
    'account', 'wallet', 'crypto', 'support', 'service', 'billing'
]

def check_ip(hostname):
    """Check if the hostname is an IP address (v4 or v6)."""
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ipv4_pattern, hostname):
        return 1
    if ':' in hostname:
        return 1
    return 0

def get_features(url):
    """
    Extracts numerical features from a URL string.
    Returns a dictionary of features suitable for the model.
    """
    # Normalize URL representation for parsing
    parsed_url = url
    if not (url.startswith('http://') or url.startswith('https://')):
        parsed_url = 'http://' + url
        
    try:
        parsed = urlparse(parsed_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = ''
        path = ''
        query = ''
        scheme = ''

    # Feature extraction
    url_len = len(url)
    host_len = len(hostname)
    
    is_https = 1 if scheme == 'https' else 0
    have_ip = check_ip(hostname)
    have_at = 1 if '@' in url else 0
    
    # Dots and hyphens in domain/hostname
    nb_dots = hostname.count('.')
    nb_hyphens = hostname.count('-')
    
    # Slashes, questions, equals in full URL
    nb_slashes = url.count('/')
    nb_question = url.count('?')
    nb_equal = url.count('=')
    
    # Prefix/suffix: presence of hyphen in domain
    prefix_suffix = 1 if '-' in hostname else 0
    
    # URL shortening detection
    shortening_service = 0
    for service in SHORTENING_SERVICES:
        if service in hostname or service in url:
            shortening_service = 1
            break
            
    # Suspicious keywords in URL
    url_lower = url.lower()
    suspicious_word_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)
    suspicious_word_present = 1 if suspicious_word_count > 0 else 0
    
    # Digits and letters
    nb_digits = sum(c.isdigit() for c in url)
    nb_letters = sum(c.isalpha() for c in url)
    
    return {
        'url_length': url_len,
        'hostname_length': host_len,
        'is_https': is_https,
        'have_ip': have_ip,
        'have_at': have_at,
        'nb_dots': nb_dots,
        'nb_hyphens': nb_hyphens,
        'nb_slashes': nb_slashes,
        'nb_question': nb_question,
        'nb_equal': nb_equal,
        'prefix_suffix': prefix_suffix,
        'shortening_service': shortening_service,
        'suspicious_words': suspicious_word_present,
        'nb_digits': nb_digits,
        'nb_letters': nb_letters
    }

def explain_features(url, features):
    """
    Analyzes the extracted features and returns a human-readable list
    of flags, explanations, and their severity (safe, warning, critical).
    """
    analysis = []
    url_lower = url.lower()

    # HTTPS check
    if features['is_https'] == 1:
        analysis.append({
            'name': 'HTTPS Encryption',
            'status': 'safe',
            'detail': 'The URL uses the secure HTTPS protocol.',
            'value': 'Secure (HTTPS)'
        })
    else:
        analysis.append({
            'name': 'HTTPS Encryption',
            'status': 'warning',
            'detail': 'The URL uses unencrypted HTTP. Phishing sites often run on plain HTTP.',
            'value': 'Insecure (HTTP)'
        })

    # IP check
    if features['have_ip'] == 1:
        analysis.append({
            'name': 'IP Address in Hostname',
            'status': 'critical',
            'detail': 'The URL uses a numerical IP address instead of a domain name. This is a common tactic to hide malicious server identities.',
            'value': 'IP Used'
        })
    else:
        analysis.append({
            'name': 'IP Address in Hostname',
            'status': 'safe',
            'detail': 'The URL correctly resolves using a domain name instead of a bare IP address.',
            'value': 'Domain Name Used'
        })

    # Length check
    if features['url_length'] > 75:
        analysis.append({
            'name': 'URL Length',
            'status': 'warning',
            'detail': f"The URL is exceptionally long ({features['url_length']} characters). Phishing sites use long URLs to hide the actual domain from the user's address bar.",
            'value': f"{features['url_length']} chars"
        })
    else:
        analysis.append({
            'name': 'URL Length',
            'status': 'safe',
            'detail': f"The URL length is standard ({features['url_length']} characters).",
            'value': f"{features['url_length']} chars"
        })

    # Suspicious words
    words_found = [word for word in SUSPICIOUS_WORDS if word in url_lower]
    if features['suspicious_words'] == 1:
        analysis.append({
            'name': 'Suspicious Keywords',
            'status': 'critical',
            'detail': f"The URL contains sensitive/phishing keywords: {', '.join(words_found)}. These are often used to spoof logins, banks, or services.",
            'value': f"Found: {len(words_found)}"
        })
    else:
        analysis.append({
            'name': 'Suspicious Keywords',
            'status': 'safe',
            'detail': 'No common phishing keywords were found in the URL.',
            'value': 'None'
        })

    # Shortening service
    if features['shortening_service'] == 1:
        analysis.append({
            'name': 'URL Shortening',
            'status': 'warning',
            'detail': 'The URL uses a redirection or shortening service. Phishing operators use these to mask the final malicious destination.',
            'value': 'Shortened'
        })

    # Domain structure (hyphens, dots)
    if features['prefix_suffix'] == 1:
        analysis.append({
            'name': 'Domain Prefix/Suffix (-)',
            'status': 'warning',
            'detail': "The domain contains a hyphen ('-'). Phishing sites frequently use hyphens to mimic authentic brand names (e.g., 'brand-support.com').",
            'value': 'Hyphen Present'
        })

    if features['nb_dots'] > 3:
        analysis.append({
            'name': 'Subdomain Count',
            'status': 'warning',
            'detail': f"The hostname contains a high number of subdomains ({features['nb_dots']} dots). This is often used to craft deep paths resembling valid domains.",
            'value': f"{features['nb_dots']} subdomains"
        })

    # `@` symbol
    if features['have_at'] == 1:
        analysis.append({
            'name': 'Symbol "@" Usage',
            'status': 'critical',
            'detail': "The URL contains an '@' symbol. The browser ignores everything before the '@' sign, redirecting the user to the domain that follows, which is a classic phishing trick.",
            'value': '@ Found'
        })

    return analysis
