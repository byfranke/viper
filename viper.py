#!/usr/bin/env python3
"""
VIPER - Threat Intelligence Tool
Fast domain discovery for attack surface mapping and threat hunting
Version: 1.0
Author: byFranke
"""

import argparse
import sys
import requests
from urllib.parse import urlparse, quote_plus
from bs4 import BeautifulSoup
import time
import re
import random
import urllib3
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import hashlib
import shutil
import tempfile
from modules import Colors, Config, render_html_template

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration
config = Config.load_config()
    def _save_txt(self, domains):
        """Save results to a text file"""
        self._validate_output_file()
        try:
            with open(str(self.output_file), 'w', encoding='utf-8') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving TXT file: {e}{Colors.RESET}", file=sys.stderr)
    
    def _save_csv(self, domains):
        """Save results to a CSV file"""
        self._validate_output_file()
        try:
            with open(str(self.output_file), 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Status Code', 'Technologies'])
                for domain in domains:
                    info = self.domain_info.get(domain, {})
                    writer.writerow([
                        domain,
                        info.get('status_code', 'N/A'),
                        ', '.join(info.get('technologies', []))
                    ])
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving CSV file: {e}{Colors.RESET}", file=sys.stderr)
    
    def _save_json(self, domains):
        """Save results to a JSON file"""
        self._validate_output_file()
        output = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_domains': len(domains),
                'filter_directory': self.filter_dir
            },
            'domains': []
        }
        for domain in domains:
            domain_info = self.domain_info.get(domain, {})
            output['domains'].append({
                'domain': domain,
                'status_code': domain_info.get('status_code', 'N/A'),
                'technologies': domain_info.get('technologies', []),
                'directory': domain_info.get('directory', self.filter_dir),
                'url': domain_info.get('url', domain)
            })
        try:
            with open(str(self.output_file), 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving JSON file: {e}{Colors.RESET}", file=sys.stderr)
    
    def _save_html(self, domains):
        """Save results to an HTML file"""
        self._validate_output_file()
        output = []
        for domain in domains:
            domain_info = self.domain_info.get(domain, {})
            output.append({
                'domain': domain,
                'status_code': domain_info.get('status_code', 'N/A'),
                'technologies': domain_info.get('technologies', []),
                'directory': domain_info.get('directory', self.filter_dir),
                'url': domain_info.get('url', domain)
            })
        context = {
            'domains': output,
            'timestamp': datetime.now().isoformat(),
            'total_domains': len(domains),
            'version': VERSION
        }
        try:
            with open(str(self.output_file), 'w', encoding='utf-8') as f:
                f.write(render_html_template('report.html', **context))
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving HTML file: {e}{Colors.RESET}", file=sys.stderr)
        
        # Compare hashes
        if current_hash == new_hash:
            print(f"{Colors.GREEN}[+] You are already running the latest version!{Colors.RESET}")
            os.remove(temp_file)
            return True
        
        # Backup current version
        backup_file = current_script + '.backup'
        print(f"{Colors.YELLOW}[*] Creating backup: {backup_file}{Colors.RESET}")
        shutil.copy2(current_script, backup_file)
        
        # Replace with new version
        print(f"{Colors.YELLOW}[*] Updating script...{Colors.RESET}")
        shutil.move(temp_file, current_script)
        
        # Set executable permissions on Unix-like systems
        if os.name != 'nt':
            os.chmod(current_script, 0o755)
        
        print(f"{Colors.GREEN}[+] Update successful!{Colors.RESET}")
        print(f"{Colors.GREEN}[+] VIPER has been updated to the latest version{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Backup saved as: {backup_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Please restart VIPER to use the new version{Colors.RESET}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[-] Network error: {e}{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}[-] Error during update: {e}{Colors.RESET}")
        return False


class ViperFinder:
    def __init__(self, limit=50, output_file=None, verbose=False, filter_dir=None, 
                 threads=5, detect_tech=False, output_format='txt', delay_min=2, delay_max=5):
        self.limit = limit
        self.output_file = output_file
        self.verbose = verbose
        self.filter_dir = filter_dir
        self.threads = threads
        self.detect_tech = detect_tech
        self.output_format = output_format
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.domains = set()
        self.filtered_domains = set()
        self.domain_info = {}  # Store detailed info for each domain
        
        # Use global configuration if available
        if config:
            self.user_agents = config.get("user_agents", [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ])
            self.blacklisted_domains = config.get("blacklisted_domains", [])
            self.search_engines = config.get("search_engines", {})
        else:
            # Default values if config is not available
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]
            self.blacklisted_domains = []
            self.search_engines = {}
        
        self.headers = self._get_headers()
        self.request_count = 0
        self.max_requests_per_source = 3
    
    def _get_headers(self):
        """Get randomized headers to avoid detection"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        }
    
    def _random_delay(self):
        """Add random delay between requests to appear more human-like"""
        delay = random.uniform(self.delay_min, self.delay_max)
        self.log(f"Waiting {delay:.2f} seconds (rate limiting)...")
        time.sleep(delay)
    
    def detect_technology(self, domain, html_content):
        """Detect web technologies from HTML content"""
        technologies = []
        html_lower = html_content.lower()
        
        # CMS Detection
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            technologies.append('WordPress')
        if 'joomla' in html_lower:
            technologies.append('Joomla')
        if 'drupal' in html_lower:
            technologies.append('Drupal')
        if 'shopify' in html_lower:
            technologies.append('Shopify')
        if 'wix.com' in html_lower:
            technologies.append('Wix')
        if 'squarespace' in html_lower:
            technologies.append('Squarespace')
        
        # Frameworks
        if 'react' in html_lower or '_react' in html_lower:
            technologies.append('React')
        if 'angular' in html_lower or 'ng-' in html_lower:
            technologies.append('Angular')
        if 'vue' in html_lower or 'vuejs' in html_lower:
            technologies.append('Vue.js')
        if 'bootstrap' in html_lower:
            technologies.append('Bootstrap')
        if 'jquery' in html_lower:
            technologies.append('jQuery')
        
        # E-commerce
        if 'magento' in html_lower:
            technologies.append('Magento')
        if 'woocommerce' in html_lower:
            technologies.append('WooCommerce')
        if 'prestashop' in html_lower:
            technologies.append('PrestaShop')
        
        # Analytics & Tracking
        if 'google-analytics' in html_lower or 'gtag' in html_lower:
            technologies.append('Google Analytics')
        if 'facebook.net/en_us/fbevents.js' in html_lower:
            technologies.append('Facebook Pixel')
        
        # Server Detection from headers
        if 'x-powered-by' in html_lower:
            match = re.search(r'x-powered-by["\s:]+([^"<\n]+)', html_lower)
            if match:
                technologies.append(f"Powered by: {match.group(1).strip()}")
        
        return technologies if technologies else ['Unknown']
    
    def check_directory(self, domain, directory):
        """Check if a specific directory/page exists on domain"""
        try:
            # Ensure domain has protocol
            if not domain.startswith(('http://', 'https://')):
                domain = f"https://{domain}"
            
            # Remove trailing slash from domain
            domain = domain.rstrip('/')
            
            # Ensure directory starts with /
            if not directory.startswith('/'):
                directory = f"/{directory}"
            
            url = f"{domain}{directory}"
            
            self.log(f"Checking: {url}")
            
            # Rotate headers
            headers = self._get_headers()
            
            # Make request with timeout
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10,
                allow_redirects=True,
                verify=False  # Skip SSL verification for speed
            )
            
            # Detect technology if enabled
            tech_detected = []
            if self.detect_tech:
                tech_detected = self.detect_technology(domain, response.text)
            
            # Store domain info
            self.domain_info[domain] = {
                'url': url,
                'status_code': response.status_code,
                'technologies': tech_detected if self.detect_tech else [],
                'directory': directory,
                'timestamp': datetime.now().isoformat()
            }
            
            # Consider successful if 200-399 status codes
            if 200 <= response.status_code < 400:
                self.log(f"✓ Found: {url} (Status: {response.status_code})")
                if self.detect_tech and tech_detected:
                    self.log(f"  Technologies: {', '.join(tech_detected)}")
                return True
            else:
                self.log(f"✗ Not found: {url} (Status: {response.status_code})")
                return False
                
        except requests.exceptions.Timeout:
            self.log(f"✗ Timeout: {url}")
            return False
        except requests.exceptions.ConnectionError:
            self.log(f"✗ Connection error: {url}")
            return False
        except Exception as e:
            self.log(f"✗ Error checking {url}: {e}")
            return False
    
    def filter_domains_by_directory(self):
        """Filter domains that have the specified directory using threading"""
        if not self.filter_dir:
            return
        
        print(f"\n{Colors.YELLOW}[*] Filtering domains with directory: {self.filter_dir}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Checking {len(self.domains)} domains with {self.threads} threads...{Colors.RESET}\n")
        
        domains_list = list(self.domains)
        total = len(domains_list)
        checked = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {
                executor.submit(self.check_directory, domain, self.filter_dir): domain 
                for domain in domains_list
            }
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                checked += 1
                
                try:
                    if future.result():
                        self.filtered_domains.add(domain)
                        tech_info = ""
                        if self.detect_tech and domain in self.domain_info:
                            techs = self.domain_info[domain].get('technologies', [])
                            if techs:
                                tech_info = f" [{', '.join(techs)}]"
                        print(f"{Colors.GREEN}[{checked}/{total}] ✓ {domain}{tech_info}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[{checked}/{total}] ✗ {domain}{Colors.RESET}")
                except Exception as e:
                    self.log(f"Error processing {domain}: {e}")
                
                # Small delay between checks
                time.sleep(random.uniform(0.3, 0.8))
        
        print(f"\n{Colors.GREEN}[+] Found {len(self.filtered_domains)} domains with '{self.filter_dir}'{Colors.RESET}\n")
    
    def log(self, message):
        """Log verbose messages"""
        if self.verbose:
            print(f"[*] {message}")
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc if parsed.netloc else parsed.path
            # Remove www. if present
            domain = re.sub(r'^www\.', '', domain)
            
            # Blacklist search engines and common non-target domains
            blacklist = [
                'duckduckgo.com',
                'bing.com',
                'google.com',
                'yahoo.com',
                'wikipedia.org',
                'facebook.com',
                'twitter.com',
                'youtube.com',
                'linkedin.com',
                'instagram.com',
                'reddit.com',
                'w3.org',
                'schema.org',
                'creativecommons.org'
            ]
            
            # Check if domain is in blacklist
            for blocked in blacklist:
                if blocked in domain.lower():
                    return None
            
            # Ensure it has protocol
            if domain and not url.startswith(('http://', 'https://')):
                return f"https://{domain}"
            return url if domain else None
        except:
            return None
    
    def _extract_links(self, soup, selector=None):
        """Extract links from BeautifulSoup object"""
        links = []
        if selector:
            elements = soup.select(selector)
        else:
            elements = soup.find_all('a', href=True)
            
        for element in elements:
            if hasattr(element, 'get'):
                href = element.get('href')
                if href and isinstance(href, str):
                    links.append(href)
        return links
    
    def search_duckduckgo(self, keyword):
        """Search domains using DuckDuckGo"""
        self.log(f"Searching on DuckDuckGo: {keyword}")
        
        try:
            # Rotate headers for each request
            self.headers = self._get_headers()
            
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(keyword)}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            # Random delay after request
            self._random_delay()
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # First try DuckDuckGo specific result links
                links = self._extract_links(soup, 'a.result__a')
                
                # If not enough results, try all links
                if len(links) < self.limit:
                    links.extend(self._extract_links(soup))
                
                # Process links
                for href in links:
                    if len(self.domains) >= self.limit:
                        break
                        
                    # Only process external links
                    if href.startswith('http') and not any(blocked in href.lower() for blocked in self.blacklisted_domains):
                            domain = self.extract_domain(href)
                            if domain:
                                self.domains.add(domain)
                                self.log(f"Found domain: {domain}")
                
        except Exception as e:
            self.log(f"Error searching DuckDuckGo: {e}")
    
    def search_bing(self, keyword):
        """Search domains using Bing"""
        self.log(f"Searching on Bing: {keyword}")
        
        try:
            # Rotate headers for each request
            self.headers = self._get_headers()
            
            url = f"https://www.bing.com/search?q={quote_plus(keyword)}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            # Random delay after request
            self._random_delay()
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract all links
                links = self._extract_links(soup)
                
                # Process links
                for href in links:
                    if len(self.domains) >= self.limit:
                        break
                        
                    # Only process external links
                    if href.startswith('http') and not any(blocked in href.lower() for blocked in self.blacklisted_domains):
                        domain = self.extract_domain(href)
                        if domain:
                            self.domains.add(domain)
                            self.log(f"Found domain: {domain}")
                            
        except Exception as e:
            self.log(f"Error searching Bing: {e}")
    
    def search_keyword(self, keyword):
        """Search domains for a keyword"""
        self.log(f"Processing keyword: {keyword}")
        
        # Try multiple sources with rate limiting
        self.search_duckduckgo(keyword)
        
        if len(self.domains) < self.limit:
            self.search_bing(keyword)
    
    def process_keywords(self, keywords):
        """Process keyword list"""
        for keyword in keywords:
            if len(self.domains) >= self.limit:
                break
            self.search_keyword(keyword.strip())
    
    def _save_file(self, mode='w', **kwargs):
        """Generic file saving helper with validation"""
        if not self.output_file:
            raise ValueError("No output file specified")
        if not isinstance(self.output_file, str):
            raise ValueError("Output file path must be a string")
        
        # Ensure directory exists
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Open file with provided mode and additional arguments
        return open(str(self.output_file), mode, **kwargs)

    def _validate_output_file(self):
        """Validate output file path"""
        if not self.output_file:
            raise ValueError("No output file specified")
        if not isinstance(self.output_file, str):
            raise ValueError("Output file path must be a string")
        
        # Ensure directory exists
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def save_results(self):
        """Save or display results in specified format"""
        # Use filtered domains if directory filter was applied
        domains_to_save = list(self.filtered_domains) if self.filter_dir else list(self.domains)
        sorted_domains = sorted(domains_to_save)[:self.limit]
        
        if not self.output_file:
            # No output file specified, just display results
            self._display_results(sorted_domains)
            return True
        
        # Save to file based on format
        try:
            self._validate_output_file()
            
            if self.output_format == 'json':
                self._save_json(sorted_domains)
            elif self.output_format == 'csv':
                self._save_csv(sorted_domains)
            elif self.output_format == 'html':
                self._save_html(sorted_domains)
            else:  # txt
                self._save_txt(sorted_domains)
            
            print(f"{Colors.GREEN}[+] {len(sorted_domains)} domains saved to: {self.output_file}{Colors.RESET}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving file: {str(e)}{Colors.RESET}", file=sys.stderr)
            return False
                
                print(f"{Colors.GREEN}[+] {len(sorted_domains)} domains saved to: {self.output_file}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[-] Error saving file: {e}{Colors.RESET}", file=sys.stderr)
                return False
        else:
            self._display_results(sorted_domains)
        
        return True
    
    def _save_json(self, domains):
        """Save results in JSON format"""
        data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_domains': len(domains),
                'filter_directory': self.filter_dir,
                'technology_detection': self.detect_tech
            },
            'domains': []
        }
        
        for domain in domains:
            domain_data = {'url': domain}
            if domain in self.domain_info:
                domain_data.update(self.domain_info[domain])
            data['domains'].append(domain_data)
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _save_csv(self, domains):
        """Save results in CSV format"""
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            if self.detect_tech or self.filter_dir:
                fieldnames = ['domain', 'status_code', 'technologies', 'directory', 'timestamp']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for domain in domains:
                    row = {'domain': domain}
                    if domain in self.domain_info:
                        info = self.domain_info[domain]
                        row['status_code'] = info.get('status_code', 'N/A')
                        row['technologies'] = ', '.join(info.get('technologies', []))
                        row['directory'] = info.get('directory', 'N/A')
                        row['timestamp'] = info.get('timestamp', 'N/A')
                    writer.writerow(row)
            else:
                writer = csv.writer(f)
                writer.writerow(['domain'])
                for domain in domains:
                    writer.writerow([domain])
    
    def _save_txt(self, domains):
        """Save results in TXT format"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for domain in domains:
                if self.filter_dir:
                    url = domain.rstrip('/') + (self.filter_dir if self.filter_dir.startswith('/') else '/' + self.filter_dir)
                    f.write(f"{url}\n")
                else:
                    f.write(f"{domain}\n")
    
    def _save_html(self, domains):
        """Save results in HTML format"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VIPER Scan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }}
        h1 {{ color: #ff4444; }}
        .header {{ margin-bottom: 30px; }}
        .info {{ color: #aaa; margin: 5px 0; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #444; padding: 12px; text-align: left; }}
        th {{ background-color: #ff4444; color: white; }}
        tr:nth-child(even) {{ background-color: #2a2a2a; }}
        tr:hover {{ background-color: #3a3a3a; }}
        .tech {{ color: #44ff44; font-size: 0.9em; }}
        .timestamp {{ color: #888; font-size: 0.8em; }}
        .footer {{ margin-top: 30px; color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>VIPER Scan Results</h1>
        <p class="info"><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p class="info"><strong>Total Domains:</strong> {len(domains)}</p>
        {f"<p class='info'><strong>Directory Filter:</strong> {self.filter_dir}</p>" if self.filter_dir else ""}
        <p class="info"><strong>Version:</strong> {VERSION}</p>
    </div>
    <table>
        <tr>
            <th>#</th>
            <th>Domain</th>
            {"<th>Status</th>" if self.filter_dir else ""}
            {"<th>Technologies</th>" if self.detect_tech else ""}
            {"<th>Timestamp</th>" if self.filter_dir else ""}
        </tr>
"""
        for idx, domain in enumerate(domains, 1):
            url = domain
            if self.filter_dir:
                url = domain.rstrip('/') + (self.filter_dir if self.filter_dir.startswith('/') else '/' + self.filter_dir)
            
            html += f"        <tr><td>{idx}</td><td><a href='{url}' target='_blank'>{domain}</a></td>"
            
            if domain in self.domain_info:
                info = self.domain_info[domain]
                if self.filter_dir:
                    html += f"<td>{info.get('status_code', 'N/A')}</td>"
                if self.detect_tech:
                    techs = ', '.join(info.get('technologies', ['Unknown']))
                    html += f"<td class='tech'>{techs}</td>"
                if self.filter_dir:
                    html += f"<td class='timestamp'>{info.get('timestamp', 'N/A')}</td>"
            
            html += "</tr>\n"
        
        html += f"""    </table>
    <div class="footer">
        <p>Generated by VIPER v{VERSION} - byFranke</p>
    </div>
</body>
</html>"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _display_results(self, domains):
        """Display results to console"""
        print(f"\n{Colors.GREEN}[+] Domains found:{Colors.RESET}\n")
        for domain in domains:
            if self.filter_dir:
                display_url = domain.rstrip('/') + (self.filter_dir if self.filter_dir.startswith('/') else '/' + self.filter_dir)
                tech_info = ""
                if self.detect_tech and domain in self.domain_info:
                    techs = self.domain_info[domain].get('technologies', [])
                    if techs:
                        tech_info = f" {Colors.YELLOW}[{', '.join(techs)}]{Colors.RESET}"
                print(f"{Colors.CYAN}{display_url}{Colors.RESET}{tech_info}")
            else:
                print(f"{Colors.CYAN}{domain}{Colors.RESET}")
        print(f"\n{Colors.GREEN}[+] Total: {len(domains)} domains{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description=f'{Colors.RED}VIPER v{VERSION}{Colors.RESET} - Fast domain discovery for Threat Intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BOLD}Examples:{Colors.RESET}
  {Colors.CYAN}Basic search:{Colors.RESET}
    %(prog)s logistics "online movies"
    %(prog)s --list keywords.txt --limit 100 --output domains.txt
  
  {Colors.CYAN}Directory filtering:{Colors.RESET}
    %(prog)s "wordpress" --dir /wp-admin --output wp-sites.txt
    %(prog)s --list targets.txt --dir /hidden_page.php -v
  
  {Colors.CYAN}Technology detection:{Colors.RESET}
    %(prog)s "e-commerce" --detect-tech --format json -o results.json
    %(prog)s "cms site" --dir /admin --detect-tech --format html
  
  {Colors.CYAN}Advanced options:{Colors.RESET}
    %(prog)s "security" --threads 10 --delay-min 1 --delay-max 3
    %(prog)s --list domains.txt --format csv --detect-tech -o report.csv

{Colors.BOLD}Output Formats:{Colors.RESET}
  txt  - Plain text list of domains (default)
  json - Structured JSON with metadata
  csv  - Spreadsheet compatible format
  html - Visual HTML report

{Colors.BOLD}Update:{Colors.RESET}
  %(prog)s --update    Check and install updates from GitHub

{Colors.YELLOW}byFranke - Threat Intelligence Tools{Colors.RESET}
        """
    )
    
    # Grupo de entrada de keywords
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        'keywords',
        nargs='*',
        help='Keywords for domain search (direct command line)'
    )
    input_group.add_argument(
        '--list', '-l',
        dest='keyword_file',
        help='File containing keyword list (one per line)'
    )
    
    # Options
    parser.add_argument(
        '--limit',
        type=int,
        default=50,
        help='Domain search limit (default: 50)'
    )
    parser.add_argument(
        '--output', '-o',
        dest='output_file',
        help='Output file to save domains (TXT format)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose mode (show debug information)'
    )
    parser.add_argument(
        '--dir', '-d',
        dest='filter_dir',
        help='Filter domains that have this directory/page (e.g., /admin, hidden_page.php, /wp-login.php)'
    )
    parser.add_argument(
        '--threads', '-t',
        type=int,
        default=5,
        help='Number of threads for directory checking (default: 5)'
    )
    parser.add_argument(
        '--detect-tech',
        action='store_true',
        help='Detect web technologies (CMS, frameworks, etc.)'
    )
    parser.add_argument(
        '--format', '-f',
        dest='output_format',
        choices=['txt', 'json', 'csv', 'html'],
        default='txt',
        help='Output format: txt, json, csv, or html (default: txt)'
    )
    parser.add_argument(
        '--delay-min',
        type=float,
        default=2.0,
        help='Minimum delay between requests in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--delay-max',
        type=float,
        default=5.0,
        help='Maximum delay between requests in seconds (default: 5.0)'
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='Check and install updates from GitHub'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'VIPER v{VERSION} - byFranke'
    )
    
    args = parser.parse_args()
    
    # Handle update flag
    if args.update:
        update_viper()
        sys.exit(0)
    
    # Validations
    if args.limit <= 0:
        print(f"{Colors.RED}[-] Limit must be greater than 0{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    if args.delay_min < 0 or args.delay_max < 0:
        print(f"{Colors.RED}[-] Delays must be positive numbers{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    if args.delay_min > args.delay_max:
        print(f"{Colors.RED}[-] Minimum delay cannot be greater than maximum delay{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    if args.threads < 1:
        print(f"{Colors.RED}[-] Threads must be at least 1{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    # Collect keywords
    keywords = []
    
    if args.keyword_file:
        try:
            with open(args.keyword_file, 'r', encoding='utf-8') as f:
                keywords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[-] File not found: {args.keyword_file}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading file: {e}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        keywords = args.keywords
    
    if not keywords:
        print(f"{Colors.RED}[-] No keywords provided{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    # Banner
    print(f"""{Colors.RED}{Colors.BOLD}
                                                                
                ██╗   ██╗██╗██████╗ ███████╗██████╗                     
                ██║   ██║██║██╔══██╗██╔════╝██╔══██╗                    
                ██║   ██║██║██████╔╝█████╗  ██████╔╝                    
                ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗                    
                 ╚████╔╝ ██║██║     ███████╗██║  ██║                    
                  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝                    
{Colors.RESET}                                                                
{Colors.WHITE}               Threat Intelligence & Attack Surface Mapping{Colors.RESET}         
{Colors.CYAN}                    Fast Domain Discovery for Hunting{Colors.RESET}               
                                                                
{Colors.YELLOW}                         v{VERSION} - byFranke{Colors.RESET}                      
                                                                
    """)
    
    print(f"[*] Keywords: {len(keywords)}")
    print(f"[*] Limite: {args.limit}")
    print(f"[*] Output: {args.output_file if args.output_file else 'STDOUT'}\n")
    
    # Execute search
    finder = ViperFinder(
        limit=args.limit,
        output_file=args.output_file,
        verbose=args.verbose,
        filter_dir=args.filter_dir,
        threads=args.threads
    )
    
    try:
        finder.process_keywords(keywords)
        
        # Apply directory filter if specified
        if args.filter_dir:
            finder.filter_domains_by_directory()
        
        finder.save_results()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Operation cancelled by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
