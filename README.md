# 🕵️‍♂️ Favicon_Hasher

Favicon_Hasher is a lightweight Python toolkit designed for Red Teamers and Bug Bounty hunters. Its primary goal is to discover the Real Origin IP of websites protected by WAFs (Web Application Firewalls) like Cloudflare, Akamai, or AWS CloudFront.

It achieves this by automating the "Favicon Hash" OSINT technique and filtering large datasets from search engines like FOFA or Shodan to find exposed infrastructure.


# 🚀 Features

This repository contains two specialized scripts:

**favicon_hasher.py**

Calculates the specific hash required to find a target's infrastructure on IoT search engines.

- Deep Dive: Shodan and FOFA do not hash raw image files. They base64-encode the favicon, insert newlines every 76 characters (MIME standard), and then calculate the MurmurHash3 (x86 32-bit) checksum. Standard hashing tools will fail to match Shodan's database. This script handles that specific formatting automatically.

- Smart Detection: Automatically extracts favicon URLs from HTML <link> tags if a direct image URL isn't provided.

**filter_out.py (Analyzer)**

Parses CSV exports from FOFA/Shodan to identify high-probability origin IPs.

- Noise Reduction: Automatically ignores IPs belonging to known CDNs (Cloudflare, Akamai, Fastly, etc.), saving you from manual checking.

- Critical Asset Tagging: Scans titles and hostnames for keywords like admin, gray (staging), dev, backend, or manage, highlighting them as CRITICAL.

- Verdict System: Classifies every IP as "Potential Origin", "Shared Hosting", or "Ignored".


# 📦 Installation

**Prerequisites**

1. Python 3.x

2. pip (Python Package Installer)

**Install Dependencies**

Only favicon_hasher.py requires external libraries. filter_out.py runs with standard libraries.

# Install requirements

**pip install mmh3 requests beautifulsoup4**

# Clone the repository

'git clone https://github.com/codebutut/favicon_hasher.git'
'cd favicon_hasher'

🛠️ Usage & Examples

Step 1: Get the Favicon Hash

Mode A: Hashing from a URL (-u)

This is the most common method. You can provide either the main website URL or the direct link to the favicon image.

Command:

python3 favicon_hasher.py -u https://target-site.com

What happens:

The script connects to https://example.com.

==> It parses the HTML to look for tags like <link rel="icon" href="...">.

==> If found, it downloads that specific image.

==> If not found, it attempts to download https://example.com/favicon.ico as a fallback.

==> It calculates and displays the hash.

Mode B: Hashing a Local File (-f)

Use this if you have manually downloaded the favicon or if the target website is not reachable from your current network (e.g., you are analyzing an internal file).

python favicon_hasher.py -f my_downloaded_icon.ico

===> Interpreting the Output

When the script runs successfully, you will see output like this:

========================================
[SUCCESS] Hash Calculated!
========================================
Target:       [https://www.google.com/favicon.ico](https://www.google.com/favicon.ico)
File Size:    5430 bytes
MurmurHash3:  708578229
----------------------------------------
Search Queries:
Shodan:       http.favicon.hash:708578229
Zoomeye:      iconhash:"708578229"
Fofa:         icon_hash="708578229"
========================================

How to use the Hash

*** Copy the query string for your preferred search engine:

*** Shodan: Go to shodan.io and paste ==> http.favicon.hash:708578229.

*** FOFA: Go to fofa.info and paste ==> icon_hash="708578229".

===> The Goal:

If the search results return IP addresses that are not Cloudflare/CDN IPs (e.g., they belong to AWS, DigitalOcean, or a residential ISP), you have likely found the Origin Server.

===> Troubleshooting

SSL Errors: The script is configured to ignore SSL verification warnings (verify=False) to ensure it works even on misconfigured targets.

"No icon tag found": This means the script couldn't find a declared favicon in the HTML and the fallback /favicon.ico did not exist (404). In this case, try to manually find the image URL in your browser (Right-click image -> Copy Image Link) and use the -u flag with the direct link.

Hash Mismatch: If you calculate a hash but Shodan shows 0 results, check if the website serves different icons to different User-Agents. The script uses a standard Chrome User-Agent.

===> Why MurmurHash3?

Shodan uses a specific hashing algorithm:

*** Take the image bytes.

*** Encode them to Base64.

*** Insert a newline (\n) every 76 characters.

*** Calculate the MurmurHash3 (x86 32-bit) checksum.

Standard tools often miss step #3 (the newlines), resulting in an incorrect hash. This script handles that formatting automatically to ensure compatibility with Shodan.

Step 3: Analyze Results

Use filter_out.py to process the CSV file and find the real IP.

Command:

# Syntax: python filter_out.py <path_to_csv>

python3 filter_out.py fofa_results_export.csv

Output:

[*] Analyzing fofa_results_export.csv...
IP Address           | Org                       | Title/Domain                             | Verdict
----------------------------------------------------------------------------------------------------
169.136.118.29       | NETSTAR SG PTE. LTD.      | 信令接入配置平台 (Signaling Access...)     | CRITICAL ASSET
164.90.98.96         | NETSTAR SG PTE. LTD.      | CDN管理系统 (CDN Management System)       | CRITICAL ASSET
164.90.114.30        | NETSTAR SG PTE. LTD.      | activity.bigo.tv                         | POTENTIAL ORIGIN
----------------------------------------------------------------------------------------------------
[*] Analysis Complete. Found 3 potential origin candidates.


📝 Script Deep Dive

This script uses requests to fetch data and BeautifulSoup to parse HTML. It is robust against:

    *** Relative URLs: Handles /assets/icon.png correctly.

    *** SSL Errors: Ignores self-signed certificate errors (common in internal infra).

    *** Missing Headers: Mimics a standard browser User-Agent.

filter_out.py

This script uses Python's built-in csv module.

    *** CDN Filtering: It checks the 'org' column against a hardcoded list of major CDN providers (CLOUDFLARE, AKAMAI, AMAZON, etc.).

    *** Keyword Scoring: It scores rows based on dangerous keywords in the title or host fields.

    *** Verdict Logic:

        *** Green: Non-CDN IP (Likely Origin).

        *** Red: Non-CDN IP + Sensitive Keyword (High Priority).

        *** Yellow: Shared Hosting (GoDaddy, Namecheap) - often false positives or marketing sites.


⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. Using these tools to scan targets without permission may violate local laws. The authors are not responsible for misuse.
