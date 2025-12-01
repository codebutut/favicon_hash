#!/usr/bin/env python3
"""
Favicon Hash Calculator for OSINT (Shodan/Censys/Zoomeye)
---------------------------------------------------------
Author: Gemini
Description: 
    Calculates the MurmurHash3 checksum of a favicon in the specific format 
    used by Shodan. It handles local files, direct image URLs, and 
    automatically extracts favicons from website HTML.

Dependencies:
    pip install mmh3 requests beautifulsoup4
"""

import sys
import argparse
import mmh3
import requests
import codecs
import base64
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    print(f"{Colors.HEADER}{Colors.BOLD}Favicon Hash Calculator for OSINT{Colors.ENDC}")
    print("-" * 40)

def get_shodan_hash(content):
    """
    Calculates the hash using Shodan's specific algorithm:
    1. Base64 encode the content.
    2. Insert newlines (\\n) every 76 characters.
    3. Calculate MurmurHash3 (x86 32-bit).
    
    Note: codecs.encode(data, 'base64') automatically handles the 
    newline insertion expected by Shodan.
    """
    b64_data = codecs.encode(content, "base64")
    return mmh3.hash(b64_data)

def extract_favicon_url(target_url, html_content):
    """
    Parses HTML content to find the link rel="icon" tag.
    Returns the absolute URL of the favicon.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # List of common rel attributes for favicons
    icon_rels = ['icon', 'shortcut icon', 'apple-touch-icon', 'apple-touch-icon-precomposed']
    
    link = None
    for rel in icon_rels:
        link = soup.find('link', rel=lambda x: x and rel in x.lower().split())
        if link:
            break
            
    if link and link.get('href'):
        favicon_path = link.get('href')
        # Handle relative URLs (e.g., /static/img/icon.png)
        absolute_url = urljoin(target_url, favicon_path)
        return absolute_url
    
    return None

def fetch_from_url(url, timeout=10):
    """
    Fetches the favicon from a URL. handles both direct image links
    and website roots (by parsing HTML).
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        print(f"{Colors.BLUE}[*] Connecting to {url}...{Colors.ENDC}")
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Scenario A: User provided a direct link to an image
        if 'image' in content_type or url.endswith(('.ico', '.png', '.jpg', '.svg')):
            return response.content, url
            
        # Scenario B: User provided a website root, need to find the icon
        if 'text/html' in content_type:
            print(f"{Colors.BLUE}[*] Detected HTML content. Searching for favicon link...{Colors.ENDC}")
            detected_icon_url = extract_favicon_url(url, response.content)
            
            if detected_icon_url:
                print(f"{Colors.GREEN}[+] Found declared favicon: {detected_icon_url}{Colors.ENDC}")
                icon_response = requests.get(detected_icon_url, headers=headers, timeout=timeout, verify=False)
                return icon_response.content, detected_icon_url
            else:
                # Fallback to default /favicon.ico
                fallback_url = urljoin(url, '/favicon.ico')
                print(f"{Colors.WARNING}[!] No icon tag found. Trying fallback: {fallback_url}{Colors.ENDC}")
                fallback_response = requests.get(fallback_url, headers=headers, timeout=timeout, verify=False)
                if fallback_response.status_code == 200:
                    return fallback_response.content, fallback_url
                
    except requests.exceptions.SSLError:
        print(f"{Colors.FAIL}[-] SSL Error. Try checking the URL or ignoring SSL verify (already disabled in script).{Colors.ENDC}")
    except requests.exceptions.ConnectionError:
        print(f"{Colors.FAIL}[-] Connection failed. Host might be down or unreachable.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] Error: {str(e)}{Colors.ENDC}")
        
    return None, None

def process_local_file(filepath):
    """Reads bytes from a local file."""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"{Colors.FAIL}[-] File not found: {filepath}{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.FAIL}[-] Error reading file: {str(e)}{Colors.ENDC}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Calculate Favicon MurmurHash3 for OSINT")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help="Target URL (e.g., https://example.com or https://example.com/favicon.ico)")
    group.add_argument('-f', '--file', help="Local favicon file path")
    
    args = parser.parse_args()
    
    # Suppress InsecureRequestWarning for cleaner output
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    print_banner()
    
    favicon_data = None
    source_name = ""

    if args.url:
        favicon_data, source_name = fetch_from_url(args.url)
    elif args.file:
        favicon_data = process_local_file(args.file)
        source_name = args.file

    if favicon_data:
        # Calculate Hash
        mmh3_hash = get_shodan_hash(favicon_data)
        
        print("\n" + "="*40)
        print(f"{Colors.GREEN}[SUCCESS] Hash Calculated!{Colors.ENDC}")
        print("="*40)
        print(f"Target:       {source_name}")
        print(f"File Size:    {len(favicon_data)} bytes")
        print(f"MurmurHash3:  {Colors.BOLD}{mmh3_hash}{Colors.ENDC}")
        print("-" * 40)
        print(f"{Colors.HEADER}Search Queries:{Colors.ENDC}")
        print(f"Shodan:       http.favicon.hash:{mmh3_hash}")
        print(f"Zoomeye:      iconhash:\"{mmh3_hash}\"")
        print(f"Fofa:         icon_hash=\"{mmh3_hash}\"")
        print("="*40 + "\n")
    else:
        print(f"{Colors.FAIL}[-] Failed to retrieve favicon data.{Colors.ENDC}")

if __name__ == "__main__":
    main()