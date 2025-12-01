import csv
import argparse
import sys

# List of common CDNs to filter out (Noise)
CDN_NETWORKS = [
    "CLOUDFLARE", "AKAMAI", "FASTLY", "AMAZON", "GOOGLE", "MICROSOFT", 
    "ALICLOUD", "CDNETWORKS", "INCAPSULA", "SUCURI"
]

# Keywords that indicate high-value targets in Titles or Domains
INTERESTING_KEYWORDS = [
    "admin", "login", "system", "dashboard", "dev", "staging", "test", 
    "prod", "internal", "config", "management", "vpn", "git", "gray", 
    "back", "backend", "api", "console", "管理", "后台", "系统"
]

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def analyze_csv(file_path):
    print(f"{Colors.BLUE}[*] Analyzing {file_path}...{Colors.ENDC}")
    print(f"{'IP Address':<20} | {'Org':<25} | {'Title/Domain':<40} | {'Verdict'}")
    print("-" * 100)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            
            hits = 0
            
            for row in reader:
                ip = row.get('ip', 'N/A')
                org = row.get('org', '').upper()
                title = row.get('title', '')
                domain = row.get('domain', '')
                host = row.get('host', '')
                
                # Check 1: Is it a known CDN?
                is_cdn = any(cdn in org for cdn in CDN_NETWORKS)
                
                # Check 2: Is the Title interesting?
                is_interesting = any(kw.lower() in title.lower() for kw in INTERESTING_KEYWORDS) or \
                                 any(kw.lower() in host.lower() for kw in INTERESTING_KEYWORDS)

                if is_cdn:
                    # Skip noise usually, or print in grey if verbose
                    continue
                
                # Determine Verdict
                verdict = f"{Colors.GREEN}POTENTIAL ORIGIN{Colors.ENDC}"
                
                if is_interesting:
                    verdict = f"{Colors.RED}{Colors.BOLD}CRITICAL ASSET{Colors.ENDC}"
                elif "GO-DADDY" in org or "NAMECHEAP" in org:
                    verdict = f"{Colors.YELLOW}Shared Hosting{Colors.ENDC}"

                # Print Finding
                display_name = title[:35] + "..." if len(title) > 35 else title
                if not display_name:
                    display_name = host
                    
                print(f"{ip:<20} | {org[:25]:<25} | {display_name:<40} | {verdict}")
                hits += 1

            if hits == 0:
                print(f"{Colors.YELLOW}[!] No obvious origin IPs found. Target might be fully behind CDN.{Colors.ENDC}")
            else:
                print("-" * 100)
                print(f"{Colors.BLUE}[*] Analysis Complete. Found {hits} potential origin candidates.{Colors.ENDC}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error reading file: {e}{Colors.ENDC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze FOFA CSV for Origin IPs")
    parser.add_argument("file", help="Path to the FOFA CSV file")
    args = parser.parse_args()
    
    analyze_csv(args.file)