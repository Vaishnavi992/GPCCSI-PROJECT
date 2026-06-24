"""
CyberShield — Feature Extractor v3
====================================
60 features (up from 45):
  NEW: port detection, hex encoding, path depth, redirect params,
       brand-in-subdomain, obfuscated IP, executable extension,
       base64-in-query, vowel ratio, unicode chars, multi-protocol,
       suspicious country TLD, query value length, external word count
"""
import re, math, urllib.parse
from collections import Counter

SHORTENERS = {
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','rebrand.ly',
    'is.gd','buff.ly','ift.tt','j.mp','su.pr','cli.gs','tr.im','snipurl.com',
    'tiny.cc','url4.eu','u.to','qr.io','me-qr.com','rb.gy','cutt.ly','v.gd',
}
HIGH_RISK_TLDS = {
    'tk','ml','ga','cf','gq','pw','xyz','top','club','online','site','tech',
    'space','work','click','download','link','email','biz','mobi','party',
    'icu','vip','win','loan','racing','trade','date','review','stream',
    'gdn','bid','accountant','faith','cricket','science','kim','country',
    'diet','men','ninja','rocks','tips','wtf','zip','mov',
}
# Country TLDs frequently abused in phishing
SUSPICIOUS_COUNTRY_TLDS = {'cn','ru','br','ua','ro','su','cc','to','ws','bz','la'}
FREE_HOSTING = {
    '000webhostapp.com','weebly.com','wixsite.com','blogspot.com',
    'wordpress.com','pages.dev','netlify.app','vercel.app','github.io',
    'glitch.me','replit.co','herokuapp.com','firebaseapp.com','web.app',
    'azurewebsites.net','pythonanywhere.com','ngrok.io','loca.lt',
    'surge.sh','render.com','fly.dev','railway.app',
}
GENERIC_PHISH = [
    'login','signin','verify','account','update','secure','password',
    'credential','confirm','wallet','prize','winner','limited','urgent',
    'suspended','unusual','billing','invoice','webmail','webscr','checkout',
    'validate','unlock','reset','recover','reactivate','suspend','alert',
    'notice','important','action','required','immediately','expire',
]
BRAND_NAMES = [
    'paypal','amazon','apple','google','microsoft','facebook','instagram',
    'netflix','ebay','bank','dropbox','icloud','chase','wellsfargo','citibank',
    'youtube','twitter','linkedin','whatsapp','tiktok','coinbase','binance',
    'blockchain','cryptocurrency','nft','defi','metamask','dhl','fedex','ups',
    'usps','irs','ssa','medicare','visa','mastercard','amex',
]
EXEC_EXTENSIONS = {'exe','bat','cmd','vbs','ps1','sh','msi','dll','scr','jar','py','rb'}
REDIRECT_PARAMS = {'redirect','return','url','next','goto','target','redir','continue','forward'}

def _entropy(s):
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def _is_ip(h): return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h))

def _is_obfuscated_ip(url):
    # hex IP: 0xC0A80101, octal: 0300.0250.01.01, decimal: 3232235777
    return bool(
        re.search(r'0x[0-9a-fA-F]{8}', url) or
        re.search(r'\b\d{8,10}\b', url) or
        re.search(r'0\d{3}\.\d+\.\d+\.\d+', url)
    )

def _dga_score(domain):
    if not domain or len(domain) < 5: return 0.0
    d      = domain.lower()
    vowels = sum(1 for c in d if c in 'aeiou')
    alpha  = sum(1 for c in d if c.isalpha())
    if alpha == 0: return 0.5
    vowel_r = vowels / alpha
    ent     = _entropy(d)
    return round(
        min(1.0, (len(d)-5)/20) * 0.3 +
        max(0.0, 0.35 - vowel_r) / 0.35 * 0.4 +
        min(1.0, (ent-2.5)/2.0) * 0.3,
    4)

def _count_external_words(url, min_len=4):
    """Count recognizable English words in the URL (legit sites have more)."""
    COMMON = {
        'login','home','page','user','admin','help','about','contact','search',
        'news','blog','shop','store','product','service','support','account',
        'secure','email','mail','web','site','link','click','free','download',
        'update','install','view','open','read','post','comment','share',
        'google','apple','amazon','paypal','bank','credit','card','online',
    }
    tokens = re.split(r'[^a-zA-Z]', url.lower())
    return sum(1 for t in tokens if len(t) >= min_len and t in COMMON)

def extract_features(url: str) -> dict:
    url      = str(url).strip()
    norm_url = url if '://' in url else 'http://' + url
    try:
        p        = urllib.parse.urlparse(norm_url)
        scheme   = p.scheme.lower()
        hostname = (p.hostname or '').lower()
        port     = p.port
        path     = p.path or ''
        query    = p.query or ''
        fragment = p.fragment or ''
    except Exception:
        return {k: 0 for k in FEATURE_NAMES}

    clean  = hostname.replace('www.','')
    parts  = clean.split('.') if clean else ['']
    tld    = parts[-1] if len(parts) > 1 else ''
    root   = '.'.join(parts[-2:]) if len(parts) >= 2 else clean
    sub    = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    primary = parts[0] if parts else ''

    f = {}

    # ── Lengths ───────────────────────────────────────────────────────────────
    f['url_length']      = len(url)
    f['hostname_length'] = len(hostname)
    f['path_length']     = len(path)
    f['query_length']    = len(query)
    f['fragment_length'] = len(fragment)

    # ── Counts ────────────────────────────────────────────────────────────────
    f['num_dots']           = url.count('.')
    f['num_hyphens']        = url.count('-')
    f['num_underscores']    = url.count('_')
    f['num_slashes']        = url.count('/')
    f['num_question_marks'] = url.count('?')
    f['num_equals']         = url.count('=')
    f['num_ampersands']     = url.count('&')
    f['num_at_symbols']     = url.count('@')
    f['num_percent']        = url.count('%')
    f['num_digits']         = sum(1 for c in url if c.isdigit())

    # ── Ratios ────────────────────────────────────────────────────────────────
    n = len(url) or 1
    f['digit_ratio']   = f['num_digits'] / n
    f['letter_ratio']  = sum(1 for c in url if c.isalpha()) / n
    f['special_ratio'] = sum(1 for c in url if not c.isalnum() and c not in ':/-._') / n

    # ── Binary flags ──────────────────────────────────────────────────────────
    f['has_https']         = 1 if scheme == 'https' else 0
    f['has_ip']            = 1 if _is_ip(hostname) else 0
    f['has_at_symbol']     = 1 if '@' in url else 0
    f['has_double_slash']  = 1 if '//' in path else 0
    f['has_hyphen_domain'] = 1 if '-' in root else 0
    f['has_punycode']      = 1 if 'xn--' in hostname else 0
    f['has_port']          = 1 if port and port not in (80, 443) else 0
    f['has_hex_chars']     = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    f['has_unicode']       = 1 if any(ord(c) > 127 for c in url) else 0
    f['has_multi_protocol']= 1 if url.lower().count('http') > 1 else 0
    f['has_obfuscated_ip'] = 1 if _is_obfuscated_ip(url) else 0

    # ── Domain structure ──────────────────────────────────────────────────────
    f['num_subdomains']           = max(0, len(parts) - 2)
    f['tld_length']               = len(tld)
    f['is_high_risk_tld']         = 1 if tld in HIGH_RISK_TLDS else 0
    f['is_suspicious_country_tld']= 1 if tld in SUSPICIOUS_COUNTRY_TLDS else 0
    f['is_shortened_url']         = 1 if root in SHORTENERS else 0
    f['is_free_hosting']          = 1 if any(root.endswith(h) or root == h for h in FREE_HOSTING) else 0
    f['domain_in_path']           = 1 if root and root in path.lower() else 0
    f['hostname_has_digits']      = 1 if any(c.isdigit() for c in clean) else 0
    f['digit_in_domain']          = sum(1 for c in primary if c.isdigit()) / max(1, len(primary))
    f['brand_in_subdomain']       = 1 if any(b in sub.lower() for b in BRAND_NAMES) else 0

    # ── DGA ───────────────────────────────────────────────────────────────────
    f['dga_score']       = _dga_score(primary)
    f['domain_entropy']  = round(_entropy(primary), 4)
    f['repeated_chars']  = max((primary.count(c) for c in set(primary)), default=0) / max(1, len(primary))
    vowels_in_domain     = sum(1 for c in primary if c in 'aeiou')
    f['vowel_ratio']     = vowels_in_domain / max(1, len(primary))

    # ── Entropy ───────────────────────────────────────────────────────────────
    f['url_entropy']      = round(_entropy(url), 4)
    f['hostname_entropy'] = round(_entropy(hostname), 4)
    f['path_entropy']     = round(_entropy(path), 4)

    # ── Path structure ────────────────────────────────────────────────────────
    f['path_depth']  = len([s for s in path.split('/') if s])
    ext_match        = re.search(r'\.([a-z0-9]{1,6})$', path.lower())
    f['has_extension']      = 1 if ext_match else 0
    f['extension_len']      = len(ext_match.group(1)) if ext_match else 0
    f['has_exec_extension'] = 1 if (ext_match and ext_match.group(1) in EXEC_EXTENSIONS) else 0

    # ── Query params ──────────────────────────────────────────────────────────
    params = urllib.parse.parse_qs(query)
    f['num_params']           = len(params)
    f['query_key_avg_length'] = sum(len(k) for k in params) / len(params) if params else 0
    f['query_val_avg_length'] = (
        sum(len(v[0]) for v in params.values() if v) / len(params) if params else 0
    )
    f['has_redirect_param']   = 1 if any(k.lower() in REDIRECT_PARAMS for k in params) else 0
    # Base64-like value in query (long alphanumeric strings)
    f['has_base64_query']     = 1 if any(
        len(v[0]) > 20 and re.match(r'^[A-Za-z0-9+/=_-]+$', v[0])
        for v in params.values() if v
    ) else 0

    # ── Keyword features ──────────────────────────────────────────────────────
    url_low  = url.lower()
    pq_low   = (sub + '/' + path + '?' + query).lower()
    f['phishing_keyword_count'] = (
        sum(1 for w in GENERIC_PHISH if w in url_low) +
        sum(1 for b in BRAND_NAMES   if b in pq_low)
    )
    f['has_phishing_keywords']  = 1 if f['phishing_keyword_count'] > 0 else 0
    f['external_word_count']    = _count_external_words(url)

    # ── Longest token ─────────────────────────────────────────────────────────
    tokens = re.split(r'[^a-zA-Z0-9]', url)
    f['longest_token_len'] = max((len(t) for t in tokens if t), default=0)

    return f


FEATURE_NAMES = [
    # Lengths (5)
    'url_length','hostname_length','path_length','query_length','fragment_length',
    # Counts (11)
    'num_dots','num_hyphens','num_underscores','num_slashes','num_question_marks',
    'num_equals','num_ampersands','num_at_symbols','num_percent','num_digits',
    # Ratios (3)
    'digit_ratio','letter_ratio','special_ratio',
    # Binary flags (11)
    'has_https','has_ip','has_at_symbol','has_double_slash','has_hyphen_domain',
    'has_punycode','has_port','has_hex_chars','has_unicode','has_multi_protocol',
    'has_obfuscated_ip',
    # Domain structure (10)
    'num_subdomains','tld_length','is_high_risk_tld','is_suspicious_country_tld',
    'is_shortened_url','is_free_hosting','domain_in_path','hostname_has_digits',
    'digit_in_domain','brand_in_subdomain',
    # DGA (4)
    'dga_score','domain_entropy','repeated_chars','vowel_ratio',
    # Entropy (3)
    'url_entropy','hostname_entropy','path_entropy',
    # Path (3)
    'path_depth','has_extension','extension_len','has_exec_extension',
    # Query (5)
    'num_params','query_key_avg_length','query_val_avg_length',
    'has_redirect_param','has_base64_query',
    # Keywords (3)
    'phishing_keyword_count','has_phishing_keywords','external_word_count',
    # Token (1)
    'longest_token_len',
]


def extract_feature_vector(url: str) -> list:
    f = extract_features(url)
    return [f.get(n, 0) for n in FEATURE_NAMES]
