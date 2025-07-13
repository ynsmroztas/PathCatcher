
import subprocess
import requests
from urllib.parse import urljoin
from tqdm import tqdm
import urllib3
import argparse
from termcolor import cprint, colored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
VALID_EXTENSIONS = ['.php', '.jsp', '.aspx', '.cgi', '.html']

def banner():
    cprint("╔════════════════════════════════════════════════════╗", "magenta")
    cprint("║             🕵️  PATHCATCHER v1.4 - LFI Scanner          ║", "cyan", attrs=['bold'])
    cprint("╠════════════════════════════════════════════════════╣", "magenta")
    cprint("║  Automated URL Enumeration and Path Traversal Test ║", "cyan")
    cprint("║       Developed for Bug Bounty & Pentesting        ║", "cyan")
    cprint("║        Developed by mitsec - x.com/ynsmroztas      ║", "magenta")
    cprint("╚════════════════════════════════════════════════════╝\n", "magenta")

def get_urls(domain, tool="./gau"):
    cprint(f"[+] Collecting URLs using {tool}: {domain}", "yellow")
    try:
        result = subprocess.check_output([tool, domain], stderr=subprocess.DEVNULL)
        urls = result.decode().splitlines()
        return list(set(urls))
    except Exception as e:
        cprint(f"[-] Failed to collect URLs from {domain}: {e}", "red")
        return []

def load_payloads(payload_file):
    with open(payload_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def is_dynamic(url):
    return any(url.lower().endswith(ext) for ext in VALID_EXTENSIONS)

def send_payloads(urls, payloads, grep_filter=None, only_200=False, output_file=None):
    filtered_urls = []

    for url in urls:
        if grep_filter and grep_filter not in url:
            continue
        if is_dynamic(url):
            filtered_urls.append(url)

    cprint(f"[•] Applying payloads to {len(filtered_urls)} filtered URLs...\n", "blue", attrs=["bold"])
    headers = {'User-Agent': 'PathCatcher/1.4'}
    results = []

    for url in tqdm(filtered_urls, desc="Scanning URLs", colour="cyan"):
        for payload in payloads:
            full_url = urljoin(url, payload)
            try:
                r = requests.get(full_url, headers=headers, timeout=10, allow_redirects=False, verify=False)
                if r.status_code == 200 and ("root" in r.text or "bin/bash" in r.text or "password" in r.text):
                    line = f"[✔] POSSIBLE TRAVERSAL: {full_url} - {r.status_code} [{len(r.text)} bytes]"
                    cprint(line, "green", attrs=["bold"])
                    results.append(line)
                elif r.status_code == 200:
                    line = f"[•] 200 OK: {full_url} [{len(r.text)} bytes]"
                    if not only_200 or only_200:
                        cprint(line, "yellow")
                        results.append(line)
                elif not only_200:
                    line = f"[•] Checked: {full_url} - {r.status_code}"
                    results.append(line)
            except Exception as e:
                cprint(f"[!] Error: {full_url} -> {e}", "red")

    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(results))
        cprint(f"\n[✓] Results saved to {output_file}", "cyan", attrs=["bold"])

def main():
    banner()
    parser = argparse.ArgumentParser(description="PathCatcher - Path Traversal Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target domain (e.g. https://example.com)")
    parser.add_argument("-p", "--payloads", required=True, help="Payload file path")
    parser.add_argument("-t", "--tool", default="./gau", help="Tool to use: ./gau or ./waybackurls")
    parser.add_argument("--grep", help="Filter URLs containing this string (e.g. '?id=')")
    parser.add_argument("--only-200", action="store_true", help="Show only URLs that returned 200 OK")
    parser.add_argument("-o", "--output", help="Save results to output file")
    args = parser.parse_args()

    urls = get_urls(args.url, args.tool)
    payloads = load_payloads(args.payloads)
    send_payloads(urls, payloads, args.grep, args.only_200, args.output)

if __name__ == "__main__":
    main()
