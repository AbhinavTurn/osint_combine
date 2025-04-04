This tool performs basic OSINT gathering tasks including:

1. IP resolution for domains
2. WHOIS information gathering
3. DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
4. Common port scanning
5. HTTP header analysis
6. Basic web technology detection
7. Results saved to a JSON file for further analysis

### How to Use It

1. Install the required dependencies:
```bash
pip install python-whois dnspython requests colorama beautifulsoup4
```

2. Run the tool with a target domain or IP:
```bash
python osint_tool.py example.com
```

3. To specify an output file:
```bash
python osint_tool.py example.com -o results.json
```

### Features

- Color-coded output for better readability
- Concurrent port scanning for faster results
- Web technology detection
- Security header analysis
- JSON output for programmatic use

You can extend this tool with additional modules like:

- Subdomain enumeration
- SSL certificate analysis
- Search for email addresses
- Social media reconnaissance
- Google dorks automation
