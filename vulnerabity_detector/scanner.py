
import requests
import ssl
import socket
import re
from bs4 import BeautifulSoup
import whois
from datetime import datetime, timezone 
from urllib.parse import urlparse, quote_plus, parse_qs, urlencode
import certifi
from requests.exceptions import RequestException, SSLError, Timeout


''' Timeout for requests'''
REQUEST_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}

def clean_url(url):
    """Ensure the URL is properly formatted before making requests."""
    if not url:
        raise ValueError("URL cannot be empty.")
    url = url.strip()
    url = url.replace("'", "").replace('"', "")
    if not re.match(r'^[a-zA-Z0-9]+://', url): # More robust check for scheme
        url = "https://" + url
    
    # Prevent requests to local/internal IPs unless explicitly intended for testing such targets
    parsed_url = urlparse(url)
    if parsed_url.hostname:
        try:
            ip_address = socket.gethostbyname(parsed_url.hostname)
            if socket.inet_aton(ip_address).is_private if hasattr(socket.inet_aton, 'is_private') else \
               any(ip_address.startswith(prefix) for prefix in ("10.", "172.16.", "192.168.", "127.")):
                 # Allow if hostname is explicitly localhost or a common local alias
                if not parsed_url.hostname.lower() in ["localhost", "127.0.0.1"]:
                    # For this generic scanner, let's allow it but one might want to restrict it
                    # print(f"Warning: URL {url} resolves to a private IP address {ip_address}. Proceeding.")
                    pass

        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {parsed_url.hostname}")
        except AttributeError: # for older python if is_private is not there
            pass
            
    return url

def find_injection_params(url, default_param_name="id"):
    """Helper to find parameters in a URL to test for injection."""
    parsed_url = urlparse(url)
    # parse_qs returns a dictionary where values are lists
    query_dict = parse_qs(parsed_url.query, keep_blank_values=True) 
    params_to_test = []

    if query_dict:
        # Prioritize existing parameters
        params_to_test.extend(query_dict.keys())
    
    if default_param_name not in params_to_test:
        params_to_test.append(default_param_name)
        
    return list(set(params_to_test))

# SSL/TLS Security
def check_ssl(url):
    """Check if the website uses SSL/TLS and validate the certificate."""
    try:
        hostname = urlparse(url).netloc
        if not hostname:
            return "SSL Error⚠️: Invalid URL or no hostname specified."

        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Additional check: Expiry date of certificate
                    expiry_date_str = cert.get('notAfter')
                    if expiry_date_str:
                        expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        if expiry_date < datetime.now(timezone.utc):
                            return f"Secure (SSL Certificate Present but EXPIRED: {expiry_date_str})❌"
                    return "Secure (Valid SSL Certificate)✅"
                else:
                    return "Insecure (SSL Certificate Issue, getpeercert failed)⚠️"
    except SSLError as e:
        # Differentiate common SSL errors
        if "certificate verify failed" in str(e).lower():
            return f"SSL Error⚠️: Certificate verification failed ({e})"
        elif "hostname mismatch" in str(e).lower():
            return f"SSL Error⚠️: Hostname mismatch in certificate ({e})"
        return f"SSL Error⚠️: {str(e)}"
    except socket.timeout:
        return f"SSL Error⚠️: Connection to {hostname}:443 timed out"
    except socket.gaierror:
        return f"SSL Error⚠️: Could not resolve hostname {hostname}"
    except ConnectionRefusedError:
        return f"SSL Error⚠️: Connection refused by {hostname}:443 (HTTPS port closed or filtered?)"
    except Exception as e:
        return f"SSL Error⚠️: An unexpected error occurred: {str(e)}"

def check_headers(url):
    """
    Follows redirects and reports which of a predefined list of security headers are PRESENT.
    This check is case-insensitive for header names.
    """
    TARGET_HEADERS_LOWERCASE = [
        'content-security-policy', 'x-frame-options', 'x-content-type-options',
        'strict-transport-security', 'referrer-policy', 'permissions-policy',
        'cross-origin-opener-policy', 'cross-origin-embedder-policy'
    ]
    DISPLAY_CASING_MAP = {
        'content-security-policy': 'Content-Security-Policy', # ... and so on for all
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'strict-transport-security': 'Strict-Transport-Security',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy',
        'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
        'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy'
    }

    print(f"--- DEBUG: check_headers for {url} ---") # Overall debug start

    try:
        response = requests.get(
            url,
            headers=HEADERS, # Make sure HEADERS is defined globally
            timeout=REQUEST_TIMEOUT, # Make sure REQUEST_TIMEOUT is defined globally
            allow_redirects=True
        )
        response_headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        print(f"DEBUG: Received response header keys (lowercase): {list(response_headers_lower.keys())}") # Print all received keys

        found_headers_display_casing = []

        for target_h_lower in TARGET_HEADERS_LOWERCASE:
            print(f"DEBUG: Checking for target header: '{target_h_lower}'") # What are we looking for?
            if target_h_lower in response_headers_lower:
                print(f"DEBUG:   FOUND '{target_h_lower}' in response headers.") # Did we find it?
                display_name = DISPLAY_CASING_MAP.get(target_h_lower, target_h_lower)
                found_headers_display_casing.append(display_name)
            else:
                print(f"DEBUG:   DID NOT FIND '{target_h_lower}' in response headers.") # Why not?

        print(f"DEBUG: Found headers (for display): {found_headers_display_casing}") # What did we collect?
        print(f"DEBUG: Total target headers: {len(TARGET_HEADERS_LOWERCASE)}, Found headers: {len(found_headers_display_casing)}")

        if not found_headers_display_casing:
            return "No target security headers found from the predefined list.❌"
        elif len(found_headers_display_casing) == len(TARGET_HEADERS_LOWERCASE):
            return "All target security headers from the predefined list are present.✅"
        else:
            return found_headers_display_casing

    except RequestException as e:
        print(f"DEBUG: RequestException in check_headers: {e}")
        return f"Error Fetching Headers❌: {str(e)}"
    except Exception as e:
        print(f"DEBUG: Exception in check_headers: {e}")
        return f"Unexpected error in check_headers❌: {str(e)}"
    
# SQL Injection
def check_sql_injection(url):
    """Test for SQL Injection vulnerabilities."""
    try:
        test_payloads = [
            "' OR '1'='1", "' OR 'a'='a", "' OR 1=1--",
            "\" OR \"1\"=\"1", "\" OR 1=1 --",
            " UNION SELECT null,@@version -- ", " UNION SELECT @@VERSION, NULL -- ", # Common SQL version checks
            "SLEEP(5)", "BENCHMARK(5000000,MD5('1'))" # Time-based (harder to confirm without good baseline)
        ]
        sql_error_indicators = [
            "sql syntax", "mysql_fetch", "mysql error", "syntax error",
            "unexpected end of sql command", "unclosed quotation mark",
            "odbc drivers error", "invalid query", "pg_query", "ora-01756",
            "sql query failed", "sql server error", "database error", "unterminated string constant"
        ]

        params_to_test = find_injection_params(url, "id")
        parsed_url = urlparse(url)
        base_url_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        for param_name in params_to_test:
            original_query_dict = parse_qs(parsed_url.query)

            for payload in test_payloads:
                test_query_dict = original_query_dict.copy()
                test_query_dict[param_name] = payload # Inject payload
                
                # Rebuild query string, ensuring proper encoding of values by urlencode
                test_url = f"{base_url_path}?{urlencode(test_query_dict, doseq=True)}"

                try:
                    response = requests.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                    response_text = response.text.lower()

                    if any(indicator in response_text for indicator in sql_error_indicators):
                        return f"SQL Injection Detected! (Error Indicator)❌ (Param: {param_name}, Payload: '{payload}')"
                except Timeout:
                    continue # Or log timeout
                except RequestException:
                    continue # Or log error

        return "No obvious SQLi indicators found✅"
    except RequestException as e:
        return f"Connection Error during SQLi check⚠️: {str(e)}"
    except Exception as e:
        return f"Unexpected error during SQLi check⚠️: {str(e)}"


# Cross-Site Scripting (XSS)
def check_xss(url):
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""
    try:
        test_payloads = [
            "<script>alert('XSS')</script>", 
            "'><script>alert('XSS')</script>", 
            '"><script>alert(String.fromCharCode(88,83,83))</script>', 
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]
        for payload in test_payloads:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            if payload in response.text:
                return "XSS Vulnerability Detected!❌"
        return "Safe✅"
    except requests.exceptions.RequestException as e:
        return f"Connection Error⚠️: {str(e)}"


#OS Command Injection
def check_os_command_injection(url):
    """Test for OS Command Injection vulnerabilities with reduced false positives."""
    try:
        '''Testing payloads for command injection'''
        test_payloads = [
            "; ls",  
            "| dir",  
            "& cat /etc/passwd",  
            "`whoami`",  
        ]

        '''Indicators of command injection'''
        command_injection_indicators = [
            "command not found", 
            "permission denied",  
            "syntax error",  
            "unexpected token",  
            "sh:",  
            "bash:",  
            "error:",  
        ]

        # Unexpected output indicators
        unexpected_output_indicators = [
            "root:x:0:0:",  
            "bin:x:1:1:",  
            "usr:x:1000:1000:",  
            "etc/passwd", 
            "list of files",  
            "directory:",  
        ]

        for payload in test_payloads:
            test_url = f"{url}?cmd={payload}"
            response = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            response_text = response.text.lower()

            # Checking for command injection indicators
            has_command_injection = any(
                indicator in response_text for indicator in command_injection_indicators
            )

            # Checking for unexpected output
            has_unexpected_output = any(
                output in response_text for output in unexpected_output_indicators
            )

            if has_command_injection and has_unexpected_output:
                return "OS Command Injection Detected!❌"

        # If no indicators are found, returning safe
        return "Safe✅"
    except requests.exceptions.RequestException as e:
        return f"Connection Error⚠️: {str(e)}"

#I-FRAME Security
def check_iframe_security(url): # Renamed for clarity
    """Check for IFRAME security aspects (risky existing iframes, clickjacking defense)."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        iframes = soup.find_all("iframe")
        
        issues = []
        for iframe in iframes:
            src = iframe.get("src", "").lower()
            if "javascript:" in src or "data:" in src:
                issues.append(f"Risky IFRAME src detected ('{src[:50]}...')❌")
        
        # Check for Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        xfo = headers_lower.get('x-frame-options')
        csp = headers_lower.get('content-security-policy')

        clickjacking_protected = False
        if xfo and xfo.lower() in ['deny', 'sameorigin']:
            clickjacking_protected = True
        if csp and ('frame-ancestors' in csp.lower()):
            # Basic check, real CSP parsing is complex
            if "'none'" in csp.lower() or "'self'" in csp.lower():
                 clickjacking_protected = True
            # Could also check if frame-ancestors restricts to specific domains

        if not clickjacking_protected:
            issues.append("Missing strong Clickjacking protection (X-Frame-Options or CSP frame-ancestors 'none'/'self')⚠️")

        if issues:
            return "; ".join(issues)
        return "Safe (No obvious risky IFRAMEs found and Clickjacking defenses appear present)✅"
    except RequestException as e:
        return f"Connection Error during IFRAME check⚠️: {str(e)}"
    except Exception as e:
        return f"Unexpected error during IFRAME check⚠️: {str(e)}"


def parse_cookie_attributes_from_string(cookie_string):
    """
    Rudimentary parsing of a Set-Cookie string to get attributes.
    Note: This is basic. http.cookies.SimpleCookie is more robust but harder to use here directly.
    """
    attributes = {'samesite': None, 'secure': False, 'httponly': False}
    parts = [p.strip() for p in cookie_string.split(';')]

    for part in parts[1:]:
        part_lower = part.lower()
        if part_lower == 'secure':
            attributes['secure'] = True
        elif part_lower == 'httponly':
            attributes['httponly'] = True
        elif part_lower.startswith('samesite='):
            attributes['samesite'] = part.split('=', 1)[1].strip().lower()
    return attributes

def check_csrf_token(url):
    """Check for CSRF tokens in POST forms and SameSite cookie attributes."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        # Check 1: CSRF token in POST forms
        found_token_in_post_form = False
        if not forms:
            form_check_message = "No HTML forms found on this page."
        else:
            post_forms_found = 0
            for form in forms:
                form_method = form.get('method', 'get').lower()
                if form_method == 'post':
                    post_forms_found += 1
                    # Common CSRF token names, case-insensitive
                    csrf_input = form.find("input", {
                        "name": re.compile(r"csrf_token|csrfmiddlewaretoken|_csrf|authenticity_token|xsrf_token|_token", re.I)
                    })
                    if csrf_input:
                        found_token_in_post_form = True
                        break # Found in one POST form
            if post_forms_found == 0:
                form_check_message = "No POST forms found on this page."
            elif found_token_in_post_form:
                form_check_message = "CSRF token found in at least one POST form.✅"
            else:
                form_check_message = "No CSRF token found in detected POST form(s).⚠️"

        # Check 2: SameSite attribute on cookies
        samesite_lax_or_strict_present = False
        samesite_none_secure_present = False # Tracks valid SameSite=None; Secure
        relevant_cookies_checked = 0

        raw_set_cookie_headers = response.raw.headers.getlist('Set-Cookie') if hasattr(response.raw, 'headers') else []

        if not raw_set_cookie_headers:
            cookie_check_message = "No cookies set by this page."
        else:
            for cookie_str in raw_set_cookie_headers:
                relevant_cookies_checked +=1 # Count cookies we are inspecting
                attrs = parse_cookie_attributes_from_string(cookie_str)
                
                if attrs['samesite'] in ['lax', 'strict']:
                    samesite_lax_or_strict_present = True
                elif attrs['samesite'] == 'none' and attrs['secure']:
                    samesite_none_secure_present = True
            if samesite_lax_or_strict_present:
                cookie_check_message = "At least one cookie uses SameSite=Lax or SameSite=Strict.✅"
            elif samesite_none_secure_present: # Lower precedence than Lax/Strict for overall page safety indication
                cookie_check_message = "At least one cookie uses SameSite=None with Secure (acceptable for cross-site).✅"
            elif relevant_cookies_checked > 0:
                cookie_check_message = "No cookies found with SameSite=Lax or SameSite=Strict.⚠️"
            else: # Should not happen if raw_set_cookie_headers was not empty
                cookie_check_message = "Cookie SameSite status unclear."


        # Combine results
        if found_token_in_post_form:
            # If forms have tokens, that's the primary defense for form-based CSRF
            return f"{form_check_message} ({cookie_check_message})"
        elif samesite_lax_or_strict_present:
            # If no tokens in forms, but strong SameSite cookies, that's a good secondary defense
            return f"{form_check_message} {cookie_check_message}"
        # If neither strong tokens nor strong SameSite cookies are found, then it's more concerning
        elif "No CSRF token found" in form_check_message and "No cookies found with SameSite=Lax or SameSite=Strict" in cookie_check_message:
             return "Potential CSRF weakness: No tokens in POST forms and no strong SameSite cookies.❌"
        else: # General catch-all or less critical combinations
            return f"{form_check_message} {cookie_check_message}"

    except RequestException as e:
        return f"Connection Error during CSRF check⚠️: {str(e)}"
    except Exception as e:
        # Catching the specific AttributeError is good, but a general catch-all is also useful
        return f"Unexpected error during CSRF check⚠️: {str(e)}"
# Server Fingerprint
def check_server_info(url):
    """Detect server software and potentially outdated versions."""
    try:
        response = requests.head(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        server_header = response.headers.get('Server', '')
        x_powered_by = response.headers.get('X-Powered-By', '')
        
        info_parts = []
        if server_header:
            info_parts.append(f"Server: {server_header}")
        if x_powered_by:
            info_parts.append(f"X-Powered-By: {x_powered_by} (Consider removing/disabling)⚠️")
        outdated_checks = {
            'nginx': (re.compile(r'nginx/(\d+\.\d+(\.\d+)?)', re.I), lambda v: float(f"{v[0]}.{v[1]}") < 1.20), # e.g., Nginx < 1.20
            'Apache': (re.compile(r'Apache/((\d+)\.(\d+)(\.(\d+))?)', re.I), lambda v: (int(v[1]) < 2 or (int(v[1]) == 2 and float(f"{v[2]}.{v[4] or 0}") < 2.450))), # e.g., Apache < 2.4.50
            'IIS': (re.compile(r'IIS/(\d+\.\d+)', re.I), lambda v: float(v[0]) < 10.0) # e.g., IIS < 10.0 (Win Server 2016)
        }
        
        if server_header:
            for software, (pattern, is_outdated_func) in outdated_checks.items():
                match = pattern.search(server_header)
                if match:
                    version_str = match.group(1)
                    # Crude version parsing from regex groups for lambda
                    version_parts_str = version_str.split('.')
                    version_parts_int = [int(p) for p in version_parts_str if p.isdigit()]
                    if version_parts_int and is_outdated_func(version_parts_int):
                        info_parts.append(f"Potentially Outdated {software} Version ({version_str}) Detected❌")
                    break 
        
        return ", ".join(info_parts) if info_parts else "Server information not readily exposed or not matched.✅"
    except RequestException as e:
        return f"Error Fetching Server Info❌: {str(e)}"
    except Exception as e:
        return f"Unexpected error during Server Info check⚠️: {str(e)}"

# Session Cookie Security
# def check_session_security(url):
#     """Check for HttpOnly/Secure/SameSite flags."""
#     try:
#         response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
#         cookies = response.headers.get('Set-Cookie', '')
        
#         issues = []
#         if 'HttpOnly' not in cookies:
#             issues.append("Missing HttpOnly❌")
#         if 'Secure' not in cookies and url.startswith('https'):
#             issues.append("Missing Secure❌")
#         if 'SameSite' not in cookies:
#             issues.append("Missing SameSite❌")
        
#         return "Session Security Issues Detected: " + ", ".join(issues) if issues else "Safe✅"
#     except RequestException:
#         return "Connection Error"

# In scanner.py

import requests
import re # Make sure re is imported
from requests.exceptions import RequestException # Ensure this is imported at the top of scanner.py

# Assuming HEADERS and REQUEST_TIMEOUT are defined globally in your scanner.py

def check_session_cookie_security(url):
    """
    More robust check for HttpOnly, Secure, SameSite flags, and cookie prefixes
    in Set-Cookie headers.
    """
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True  # Allow redirects to see cookies set after redirection
        )

        # Use requests' parsed cookies if available, but also check raw headers for full details
        # as requests.cookies might not expose all attributes perfectly (e.g., raw SameSite string)

        raw_set_cookie_headers = []
        if hasattr(response.raw, 'headers'): # Ensure response.raw and response.raw.headers exist
            raw_set_cookie_headers = response.raw.headers.getlist('Set-Cookie')

        if not raw_set_cookie_headers and not response.cookies:
            return "No cookies set on this request path.✅"

        all_cookie_issues = []
        
        # Create a dictionary of parsed cookies from requests for easy attribute lookup
        parsed_cookies_dict = {cookie.name: cookie for cookie in response.cookies}

        # Iterate through raw headers to get all details, supplement with requests' parsed object
        unique_cookie_names_processed = set()

        for header_str in raw_set_cookie_headers:
            cookie_name_match = re.match(r"([^=]+)=", header_str)
            if not cookie_name_match:
                continue # Malformed cookie string

            cookie_name = cookie_name_match.group(1).strip()
            if cookie_name in unique_cookie_names_processed:
                continue # Already processed this cookie name (e.g. if set for different paths)
            unique_cookie_names_processed.add(cookie_name)

            issues_for_this_cookie = []
            
            # Get attributes from raw string parsing
            raw_attrs = {'samesite': None, 'secure': False, 'httponly': False}
            parts = [p.strip() for p in header_str.split(';')]
            for part in parts[1:]: # Skip name=value part
                part_lower = part.lower()
                if part_lower == 'secure':
                    raw_attrs['secure'] = True
                elif part_lower == 'httponly':
                    raw_attrs['httponly'] = True
                elif part_lower.startswith('samesite='):
                    raw_attrs['samesite'] = part.split('=', 1)[1].strip().lower()
            
            # Get potentially parsed attributes from requests.cookies
            parsed_cookie_obj = parsed_cookies_dict.get(cookie_name)
            
            # HttpOnly
            # requests.cookies.cookie.httponly might exist and be True/False
            is_httponly = raw_attrs['httponly'] or getattr(parsed_cookie_obj, 'httponly', False)
            if not is_httponly:
                issues_for_this_cookie.append("Missing HttpOnly")

            # Secure
            # requests.cookies.cookie.secure might exist and be True/False
            is_secure = raw_attrs['secure'] or getattr(parsed_cookie_obj, 'secure', False)
            if url.startswith('https://') and not is_secure:
                issues_for_this_cookie.append("Missing Secure attribute (on HTTPS)")
            
            # SameSite
            # Prefer raw_attrs['samesite'] as it's directly from header string.
            # getattr(parsed_cookie_obj, 'samesite', None) might exist if requests parsed it.
            samesite_value_to_check = raw_attrs['samesite']
            if samesite_value_to_check is None and parsed_cookie_obj: # Fallback if not in raw parse
                 samesite_value_to_check = getattr(parsed_cookie_obj, 'samesite', None)
                 if samesite_value_to_check: # If requests lib provided it
                     samesite_value_to_check = samesite_value_to_check.lower()


            if samesite_value_to_check is None: # Still None after checking both
                issues_for_this_cookie.append("Missing SameSite attribute")
            elif samesite_value_to_check == 'none':
                if not is_secure: # Must be Secure if SameSite=None
                    issues_for_this_cookie.append("SameSite=None without Secure attribute")
            elif samesite_value_to_check not in ['lax', 'strict']:
                issues_for_this_cookie.append(f"SameSite is '{samesite_value_to_check}' (neither Lax, Strict, nor valid None)")
            
            # Cookie Prefixes (__Secure- and __Host-)
            # These rules apply to how the cookie is SET by the server.
            if cookie_name.startswith("__Host-"):
                # Path must be '/', no Domain attribute, Secure flag must be true.
                path_match = re.search(r"Path=([^;]+)", header_str, re.IGNORECASE)
                domain_match = re.search(r"Domain=([^;]+)", header_str, re.IGNORECASE)
                path_is_root = path_match and path_match.group(1).strip() == '/'
                
                if not (is_secure and path_is_root and not domain_match):
                    issues_for_this_cookie.append(f"__Host- prefix rules potentially violated (requires Secure, Path=/, no Domain)")
            elif cookie_name.startswith("__Secure-"):
                if not is_secure:
                    issues_for_this_cookie.append(f"__Secure- prefix rules violated (requires Secure flag)")

            if issues_for_this_cookie:
                all_cookie_issues.append(f"Cookie '{cookie_name}': " + ", ".join(issues_for_this_cookie))
        
        if not unique_cookie_names_processed and response.cookies:
            # This case handles if Set-Cookie headers were not found/parsed via raw,
            # but requests.cookies (e.g. from a CookieJar filled by redirects) has items.
            # This is a simpler check based only on what requests library parsed.
            for cookie in response.cookies:
                if cookie.name in unique_cookie_names_processed: continue # Already did via raw
                unique_cookie_names_processed.add(cookie.name)
                issues_for_this_cookie = []
                if not getattr(cookie, 'httponly', False): issues_for_this_cookie.append("Missing HttpOnly")
                if url.startswith('https://') and not cookie.secure: issues_for_this_cookie.append("Missing Secure (on HTTPS)")
                
                s_val = getattr(cookie, 'samesite', None)
                if not s_val: issues_for_this_cookie.append("Missing SameSite")
                elif s_val.lower() == 'none' and not cookie.secure: issues_for_this_cookie.append("SameSite=None without Secure")
                elif s_val.lower() not in ['lax', 'strict', 'none']: issues_for_this_cookie.append(f"Invalid SameSite='{s_val}'")
                
                if cookie.name.startswith("__Host-"):
                    if not (cookie.secure and cookie.path == '/' and not cookie.domain):
                         issues_for_this_cookie.append(f"__Host- prefix rules potentially violated")
                elif cookie.name.startswith("__Secure-"):
                    if not cookie.secure:
                         issues_for_this_cookie.append(f"__Secure- prefix rules violated")

                if issues_for_this_cookie:
                    all_cookie_issues.append(f"Cookie '{cookie.name}' (requests.cookiejar): " + ", ".join(issues_for_this_cookie))


        if all_cookie_issues:
            return "Session Cookie Security Issues Detected❌: " + "; ".join(all_cookie_issues)
        
        # If we processed some cookies (either from raw or from jar) and found no issues
        if unique_cookie_names_processed:
             return "Session Cookie Security Good✅ (for observed cookies)"
        else: # No cookies found at all
             return "No cookies set on this request path.✅" # Should be same as initial check

    except RequestException as e:
        return f"Connection Error during Session Cookie check⚠️: {str(e)}"
    except Exception as e:
        return f"Unexpected error during Session Cookie check⚠️: {str(e)}"
    
# Basic Authentication Checks (largely heuristic)
def check_authentication(url):
    results = []
    try:
        login_paths = ["/login", "/admin", "/wp-login.php", "/signin", "/auth", "/user/login", "/portal"]
        # Check for common login page indicators
        found_login_page_msg = ""
        for path in login_paths:
            test_url = url.rstrip('/') + path
            try:
                response = requests.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT/2, allow_redirects=True)
                if response.status_code == 200:
                    text_lower = response.text.lower()
                    if any(kw in text_lower for kw in ["username", "password", "sign in", "log in", "user name:", "user id:"]):
                        if "csrf" in text_lower or "token" in text_lower: # Basic check for CSRF token
                            found_login_page_msg = f"Potential login page at {test_url} (seems to have form fields and possibly CSRF token)⚠️. Manual review recommended."
                        else:
                            found_login_page_msg = f"Potential login page at {test_url} (form fields detected, CSRF token presence unclear)⚠️. Manual review recommended."
                        break # Found one
            except RequestException:
                continue
        
        if found_login_page_msg:
            results.append(found_login_page_msg)
        else:
            results.append("No common login pages automatically detected or common login keywords not found.✅")

        # Very basic check for HTTP Basic/Digest Auth (401 Unauthorized with WWW-Authenticate)
        try:
            response_auth = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT/2, allow_redirects=True)
            if response_auth.status_code == 401 and 'WWW-Authenticate' in response_auth.headers:
                auth_type = response_auth.headers['WWW-Authenticate'].split(' ')[0]
                results.append(f"HTTP {auth_type} Authentication detected on base URL. Ensure strong credentials are used.⚠️")
        except RequestException:
            pass # Ignore if base URL fetch fails here

        return "; ".join(results) if results else "Basic authentication checks completed.✅"
    except Exception as e:
        return f"Error during basic authentication checks: {str(e)}⚠️"

# Basic Authorization Checks (very heuristic)
def check_authorization(url):
    results = []
    try:
        # Heuristic: Check for common admin/sensitive paths that might be exposed
        sensitive_paths = ["/admin", "/dashboard", "/config", "/logs", "/.git/", "/.env", "/backup/"]
        # Note: /.git/, /.env are more about misconfiguration leading to info exposure
        
        for path in sensitive_paths:
            test_url = url.rstrip('/') + path
            try:
                response = requests.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT/2, allow_redirects=False) # No redirects
                if response.status_code == 200:
                    # Check if it's not just a generic "not found" that returns 200 or a login page
                    text_lower = response.text.lower()
                    if any(kw in text_lower for kw in ["index of /", "listing directory", "git command", "dotenv", "backup files", "configuration settings", "admin panel"]) and \
                       not any(login_kw in text_lower for login_kw in ["login", "signin", "password"]):
                        results.append(f"Potentially sensitive path {test_url} is accessible and might expose information or functionality❌. Manual verification required.")
                elif response.status_code == 403 and path in ["/.git/", "/.env"]: # 403 on these might still indicate they exist
                     results.append(f"Path {test_url} returned 403 Forbidden. This might indicate its existence but restricted access. Review server config.⚠️")

            except RequestException:
                continue
        
        if not results:
            results.append("No obvious exposed sensitive paths detected with basic checks.✅")
        return "; ".join(results)
    except Exception as e:
        return f"Error during basic authorization checks: {str(e)}⚠️"


def get_hosting_info(url):
    data = {"IP Address": "Unknown", "Country": "Unknown", "Region": "Unknown", "City": "Unknown", "Organisation": "Unknown"}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain and parsed.path: 
            domain = parsed.path.split('/')[0] if parsed.path.startswith('/') else parsed.path.split('/')[0]
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): # If not an IP, it's problematic
                 if parsed.hostname: domain = parsed.hostname # Fallback to hostname if path trick failed
                 else:
                    data["Error"] = "Invalid domain/IP for IP lookup"
                    return data
        elif not domain and parsed.hostname:
            domain = parsed.hostname 

        if not domain:
            data["Error"] = "Could not determine domain/IP for lookup"
            return data
            
        ip_address = socket.gethostbyname(domain)
        data["IP Address"] = ip_address
        
        api_response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,org", timeout=REQUEST_TIMEOUT/2)
        api_response.raise_for_status()
        ip_data = api_response.json()

        if ip_data.get("status") == "success":
            data["Country"] = ip_data.get("country", "Unknown")
            data["Region"] = ip_data.get("regionName", "Unknown")
            data["City"] = ip_data.get("city", "Unknown")
            data["Organisation"] = ip_data.get("org", "Unknown")
        else:
            data["Geo API Error"] = ip_data.get("message", "Failed to retrieve geo data from ip-api.com")
    except socket.gaierror:
        data["IP Address"] = "Resolution Error"
        data["Error"] = f"Could not resolve domain '{domain}' to IP address."
    except RequestException as e:
        data["Error"] = f"Geo API Request Error: {str(e)}"
    except Exception as e:
        data["Error"] = f"Hosting info error: {str(e)}"
    return data

def get_domain_info(url):
    data = {"Domain Creation Date": "Unknown", "Domain Expiration Date": "Unknown", "Domain Age": "Unknown"}
    try:
        domain_name = urlparse(url).netloc
        if not domain_name:
            data["Error"] = "Invalid domain for WHOIS lookup"
            return data
        
        if domain_name.startswith("www."):
            domain_name = domain_name[len("www."):]
        parts = domain_name.split('.')
        if len(parts) > 2:
            # Heuristic: if the TLD part is common (com, org, net, etc.) or second level is common (co, ac)
            common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil']
            common_second_level = ['co', 'ac', 'gov', 'org', 'com'] # for .co.uk, .com.au etc.
            if parts[-1] in common_tlds and parts[-2] not in common_second_level :
                domain_name = '.'.join(parts[-2:])
            elif len(parts) > 2 and parts[-2] in common_second_level and parts[-1] in common_tlds :
                 domain_name = '.'.join(parts[-3:])


        domain_info = whois.whois(domain_name)

        if not any([domain_info.creation_date, domain_info.expiration_date, domain_info.registrar]):
            if domain_info.text:
                text_lower = domain_info.text.lower()
                if "pendingdelete" in text_lower or "redemptionperiod" in text_lower:
                    data["Status"] = "Domain might be in redemption or pending delete.⚠️"
                elif "no match for domain" in text_lower or "not found" in text_lower:
                    data["Error"] = f"WHOIS: Domain '{domain_name}' not found or no match."
                else:
                    data["Error"] = "WHOIS information limited or unavailable for this domain."
            else:
                 data["Error"] = f"WHOIS information not found for '{domain_name}'."
            return data # Return early if no core info

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list): creation_date = creation_date[0] if creation_date else None
        if isinstance(expiration_date, list): expiration_date = expiration_date[0] if expiration_date else None

        if creation_date and isinstance(creation_date, datetime):
            data["Domain Creation Date"] = creation_date.strftime("%Y-%m-%d")
            age_delta = datetime.now(creation_date.tzinfo) - creation_date # tz aware if possible
            age_days = age_delta.days
            if age_days >= 0:
                years = age_days // 365
                months = (age_days % 365) // 30
                data["Domain Age"] = f"{years} years, {months} months"
            else:
                data["Domain Age"] = "Creation date in future?"
        
        if expiration_date and isinstance(expiration_date, datetime):
            data["Domain Expiration Date"] = expiration_date.strftime("%Y-%m-%d")
            days_to_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
            if 0 <= days_to_expiry <= 30:
                data["Expiration Status"] = f"Expires soon! ({days_to_expiry} days)⚠️"
            elif days_to_expiry < 0:
                data["Expiration Status"] = "Expired!❌"
    
    except whois.parser.PywhoisError as e:
        data["Error"] = f"WHOIS lookup error for '{domain_name}': {str(e)}"
    except AttributeError:
        data["Error"] = "WHOIS information structure unexpected."
    except Exception as e:
        data["Error"] = f"Domain info error: {str(e)}"
    return data
    
def scan_website(url):
    """Run all security checks on a website."""
    scan_start_time = datetime.now()
    try:
        cleaned_url = clean_url(url)
    except ValueError as ve:
        return {"Error": f"Invalid URL: {str(ve)}", "Target URL": url}
    except Exception as e: # Catch other clean_url potential errors like socket.gaierror
        return {"Error": f"URL cleaning/validation error: {str(e)}", "Target URL": url}

    results = {"Target URL": cleaned_url}
    
    
    try:
        requests.head(cleaned_url, timeout=REQUEST_TIMEOUT/2, headers=HEADERS, allow_redirects=True)
    except RequestException as e:
        return {"Error": f"Initial connectivity check failed for {cleaned_url}: {str(e)}", **results}


   
    checks_to_run = [
        ("Hosting Info", get_hosting_info),
        ("Domain Info", get_domain_info),
        ("SSL/TLS Security", check_ssl),
        ("Security Headers", check_headers),
        ("SQL Injection", check_sql_injection),
        ("XSS (Cross-Site Scripting)", check_xss),
        ("OS Command Injection", check_os_command_injection),
        ("IFRAME Security", check_iframe_security),
        ("CSRF Protection", check_csrf_token),
        ("Server Fingerprint", check_server_info),
        ("Session Cookie Security", check_session_cookie_security),
        ("Basic Authentication Checks", check_authentication),
        ("Basic Authorization Checks", check_authorization)
    ]

    for check_name, check_function in checks_to_run:
        try:
            if check_name in ["Hosting Info", "Domain Info"]: # These return dicts
                results.update(check_function(cleaned_url))
            else:
                results[check_name] = check_function(cleaned_url)
        except Exception as e:
            # Catch errors from individual check functions
            results[check_name] = f"Error during '{check_name}' check: {str(e)}❌"
    
    # Clean up redundant "Error" keys if specific error messages exist elsewhere
    if "Error" in results and any(k != "Error" and "Error" in str(results[k]) for k in results if k != "Target URL"):
        if results["Error"].startswith("Hosting info error:") or results["Error"].startswith("Domain info error:"):
            del results["Error"]

    scan_end_time = datetime.now()
    results["Scan Duration"] = str(scan_end_time - scan_start_time)
    return results


if __name__ == "__main__":
    input_url = input("Enter the URL to scan: ").strip()
    if not input_url:
        print("Error: No URL provided.")
    else:
        print(f"\nScanning {input_url}...\n")
        scan_results = scan_website(input_url)
        print("\n--- Scan Results ---")
        for key, value in scan_results.items():
            if isinstance(value, list) and value: # For missing headers
                print(f"{key}: Missing - {', '.join(value)}❌")
            else:
                print(f"{key}: {value}")
