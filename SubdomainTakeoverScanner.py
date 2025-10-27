#!/usr/bin/env python3
"""
SubDomainTakeover Playground & POC Generator

A tool that finds potential subdomain takeovers, automatically crafts safe PoC pages,
and generates executive-style reports with remediation guidance.
This is a safe laboratory simulation and should only be used for authorized testing.
"""

import os
import sys
import json
import time
import argparse
import requests
import subprocess
import threading
from urllib.parse import urlparse
from datetime import datetime
from jinja2 import Template
from fpdf import FPDF
import dns.resolver
import dns.exception

# Configuration
DEFAULT_TIMEOUT = 10
POC_SERVER_PORT = 8080
REPORT_FILENAME = "subdomain_takeover_report.pdf"

class SubdomainTakeoverScanner:
    def __init__(self):
        self.takeover_types = {
            "github_pages": {
                "service": "GitHub Pages",
                "description": "GitHub Pages service with CNAME pointing to non-existent GitHub repo",
                "vulnerable_dns": ["github.io", "github.com"],
                "poc_template": """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Subdomain Takeover - GitHub Pages</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                        .warning {{ color: red; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <h1>Subdomain Takeover POC</h1>
                    <p class="warning">This subdomain is vulnerable to takeover!</p>
                    <p>Service: GitHub Pages</p>
                    <p>Target: {{target_subdomain}}</p>
                    <p>This is a safe demonstration of a subdomain takeover vulnerability.</p>
                </body>
                </html>
                """
            },
            "aws_s3": {
                "service": "AWS S3",
                "description": "S3 bucket referenced in DNS but not created",
                "vulnerable_dns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
                "poc_template": """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Subdomain Takeover - AWS S3</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                        .warning {{ color: red; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <h1>Subdomain Takeover POC</h1>
                    <p class="warning">This subdomain is vulnerable to takeover!</p>
                    <p>Service: AWS S3</p>
                    <p>Target: {{target_subdomain}}</p>
                    <p>This is a safe demonstration of a subdomain takeover vulnerability.</p>
                </body>
                </html>
                """
            },
            "cloudflare": {
                "service": "Cloudflare",
                "description": "Domain points to Cloudflare but not configured",
                "vulnerable_dns": ["cloudflare.com", "cloudflare.net"],
                "poc_template": """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Subdomain Takeover - Cloudflare</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                        .warning {{ color: red; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <h1>Subdomain Takeover POC</h1>
                    <p class="warning">This subdomain is vulnerable to takeover!</p>
                    <p>Service: Cloudflare</p>
                    <p>Target: {{target_subdomain}}</p>
                    <p>This is a safe demonstration of a subdomain takeover vulnerability.</p>
                </body>
                </html>
                """
            },
            "heroku": {
                "service": "Heroku",
                "description": "Domain points to Heroku app that doesn't exist",
                "vulnerable_dns": ["herokuapp.com"],
                "poc_template": """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Subdomain Takeover - Heroku</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                        .warning {{ color: red; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <h1>Subdomain Takeover POC</h1>
                    <p class="warning">This subdomain is vulnerable to takeover!</p>
                    <p>Service: Heroku</p>
                    <p>Target: {{target_subdomain}}</p>
                    <p>This is a safe demonstration of a subdomain takeover vulnerability.</p>
                </body>
                </html>
                """
            }
        }
        self.vulnerable_subdomains = []
        self.scan_results = []

    def check_dns_record(self, subdomain):
        """Check DNS records for the subdomain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Check A records
            try:
                a_records = resolver.resolve(subdomain, 'A')
                a_values = [str(rdata) for rdata in a_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                a_values = []
            
            # Check CNAME records
            try:
                cname_records = resolver.resolve(subdomain, 'CNAME')
                cname_values = [str(rdata.target) for rdata in cname_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                cname_values = []
            
            # Check NS records
            try:
                ns_records = resolver.resolve(subdomain, 'NS')
                ns_values = [str(rdata.target) for rdata in ns_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                ns_values = []
            
            return {
                "a_records": a_values,
                "cname_records": cname_values,
                "ns_records": ns_values
            }
        except Exception as e:
            print(f"Error resolving DNS for {subdomain}: {str(e)}")
            return {"a_records": [], "cname_records": [], "ns_records": []}

    def check_takeover_opportunity(self, subdomain):
        """Check if the subdomain is vulnerable to takeover."""
        dns_info = self.check_dns_record(subdomain)
        cname_values = dns_info["cname_records"]
        
        for takeover_type, config in self.takeover_types.items():
            for cname in cname_values:
                for vulnerable_dns in config["vulnerable_dns"]:
                    if vulnerable_dns in cname.lower():
                        # Verify if the service is actually available
                        if self.verify_takeover_service(subdomain, cname, takeover_type):
                            return {
                                "type": takeover_type,
                                "service": config["service"],
                                "description": config["description"],
                                "dns_info": dns_info
                            }
        return None

    def verify_takeover_service(self, subdomain, cname, takeover_type):
        """Verify if the service is actually vulnerable."""
        try:
            # Try to resolve the CNAME target
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # For GitHub Pages, check if the repo exists
            if takeover_type == "github_pages":
                repo_name = cname.replace(".github.io", "")
                if repo_name:
                    # Check if GitHub page returns 404 (non-existent repo)
                    response = requests.get(f"https://{cname}", timeout=10)
                    if response.status_code == 404:
                        return True
                    elif "There isn't a GitHub Pages site here." in response.text:
                        return True
            
            # For S3, check if bucket exists
            elif takeover_type == "aws_s3":
                try:
                    response = requests.get(f"http://{cname}", timeout=10)
                    if response.status_code == 404 or "NoSuchBucket" in response.text:
                        return True
                except:
                    return True  # If we can't reach it, it might be vulnerable
            
            # For Heroku, check if app exists
            elif takeover_type == "heroku":
                try:
                    response = requests.get(f"https://{cname}", timeout=10)
                    if response.status_code == 404 or "herokucdn.com/error-pages/no-such-app.html" in response.text:
                        return True
                except:
                    return True
            
            # For Cloudflare, check if domain is configured
            elif takeover_type == "cloudflare":
                try:
                    response = requests.get(f"https://{subdomain}", timeout=10)
                    if response.status_code == 404 or "error 1001" in response.text.lower():
                        return True
                except:
                    return True
        
        except Exception as e:
            print(f"Error verifying takeover for {subdomain}: {str(e)}")
        
        return False

    def scan_subdomains(self, subdomain_list):
        """Scan a list of subdomains for takeover opportunities."""
        print(f"Scanning {len(subdomain_list)} subdomains for takeover opportunities...")
        
        for i, subdomain in enumerate(subdomain_list):
            print(f"[{i+1}/{len(subdomain_list)}] Checking {subdomain}...")
            
            vulnerability = self.check_takeover_opportunity(subdomain)
            if vulnerability:
                print(f"  >>> VULNERABILITY FOUND: {subdomain} ({vulnerability['service']})")
                self.vulnerable_subdomains.append({
                    "subdomain": subdomain,
                    "vulnerability": vulnerability
                })
            else:
                print(f"  >>> No vulnerability found")
        
        return self.vulnerable_subdomains

    def generate_poc_pages(self):
        """Generate Proof of Concept pages for vulnerable subdomains."""
        poc_pages = []
        
        for item in self.vulnerable_subdomains:
            subdomain = item["subdomain"]
            vulnerability = item["vulnerability"]
            takeover_type = vulnerability["type"]
            
            template = Template(self.takeover_types[takeover_type]["poc_template"])
            poc_content = template.render(target_subdomain=subdomain)
            
            poc_filename = f"poc_{subdomain.replace('.', '_').replace('-', '_')}.html"
            with open(poc_filename, 'w') as f:
                f.write(poc_content)
            
            poc_pages.append({
                "subdomain": subdomain,
                "poc_file": poc_filename,
                "vulnerability_type": vulnerability["type"],
                "service": vulnerability["service"]
            })
        
        return poc_pages

    def generate_report(self, poc_pages):
        """Generate an executive-style PDF report."""
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Subdomain Takeover Vulnerability Report', 0, 1, 'C')
        pdf.ln(5)
        
        # Report Info
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
        pdf.cell(0, 10, f'Vulnerable Subdomains Found: {len(self.vulnerable_subdomains)}', 0, 1)
        pdf.ln(10)
        
        # Findings Summary
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Executive Summary', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'During the security assessment, {len(self.vulnerable_subdomains)} subdomain(s) were identified as potentially vulnerable to takeover.', 0, 1)
        pdf.ln(5)
        
        # Vulnerability Details
        for item in self.vulnerable_subdomains:
            subdomain = item["subdomain"]
            vulnerability = item["vulnerability"]
            
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, f'Subdomain: {subdomain}', 0, 1)
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 8, f'Service: {vulnerability["service"]}', 0, 1)
            pdf.cell(0, 8, f'Type: {vulnerability["description"]}', 0, 1)
            pdf.ln(5)
        
        # Remediation Guidance
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Remediation Guidance', 0, 1)
        pdf.set_font('Arial', '', 12)
        
        for item in self.vulnerable_subdomains:
            subdomain = item["subdomain"]
            vulnerability = item["vulnerability"]
            
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, f'{subdomain} - {vulnerability["service"]}', 0, 1)
            pdf.set_font('Arial', '', 12)
            
            if vulnerability["type"] == "github_pages":
                pdf.cell(0, 8, '- Ensure GitHub Pages repository exists and is properly configured', 0, 1)
                pdf.cell(0, 8, '- Remove DNS record if GitHub Pages is no longer needed', 0, 1)
            elif vulnerability["type"] == "aws_s3":
                pdf.cell(0, 8, '- Create the S3 bucket with the correct name', 0, 1)
                pdf.cell(0, 8, '- Configure proper bucket policies and website hosting', 0, 1)
            elif vulnerability["type"] == "cloudflare":
                pdf.cell(0, 8, '- Add the domain to your Cloudflare account', 0, 1)
                pdf.cell(0, 8, '- Configure DNS settings in Cloudflare dashboard', 0, 1)
            elif vulnerability["type"] == "heroku":
                pdf.cell(0, 8, '- Create a Heroku app with the correct name', 0, 1)
                pdf.cell(0, 8, '- Ensure the app is properly deployed and running', 0, 1)
            
            pdf.ln(5)
        
        # Save report
        pdf.output(REPORT_FILENAME)
        print(f"Report saved as {REPORT_FILENAME}")

def main():
    parser = argparse.ArgumentParser(description='SubDomainTakeover Playground & POC Generator')
    parser.add_argument('-l', '--list', help='File containing list of subdomains to scan (one per line)')
    parser.add_argument('-s', '--single', help='Single subdomain to scan')
    parser.add_argument('-o', '--output', help='Output directory for POC files (default: current directory)')
    args = parser.parse_args()
    
    # Prepare subdomain list
    subdomains = []
    if args.list:
        with open(args.list, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    elif args.single:
        subdomains = [args.single]
    else:
        # Demo mode with sample subdomains
        subdomains = [
            "vulnerable.example.com",  # Example vulnerable subdomain
            "takeover-test.example.com"  # Another example
        ]
        print("Running in demo mode with sample subdomains...")
    
    if not subdomains:
        print("No subdomains provided to scan.")
        return
    
    print("Starting SubDomainTakeover Playground & POC Generator...")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SubdomainTakeoverScanner()
    
    # Scan for vulnerabilities
    vulnerable_subdomains = scanner.scan_subdomains(subdomains)
    
    if not vulnerable_subdomains:
        print("\nNo vulnerabilities found.")
        return
    
    print(f"\nFound {len(vulnerable_subdomains)} vulnerable subdomains!")
    
    # Generate POC pages
    print("\nGenerating Proof of Concept pages...")
    poc_pages = scanner.generate_poc_pages()
    
    for page in poc_pages:
        print(f"  - Generated POC for {page['subdomain']}: {page['poc_file']}")
    
    # Generate report
    print("\nGenerating executive report...")
    scanner.generate_report(poc_pages)
    
    print("\nScan complete!")
    print(f"  - Vulnerable subdomains: {len(vulnerable_subdomains)}")
    print(f"  - POC pages generated: {len(poc_pages)}")
    print(f"  - Report saved as: {REPORT_FILENAME}")
    print("\nIMPORTANT: This tool is for authorized security testing only.")
    print("Ensure you have explicit permission before scanning any domains.")

if __name__ == '__main__':
    main()
