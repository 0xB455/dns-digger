#!/usr/bin/env python3
"""
DNS Digger v1.1 - Comprehensive DNS & Mail Record Lookup for offensive purposes.

Usage Examples:

  # DNS Mode
  python3 dns-digger.py dns example.com --verbose
  python3 dns-digger.py dns -iL domainlist.txt --recursive

  # Mail Mode
  python3 dns-digger.py mail example.com --validate
  python3 dns-digger.py mail -iL input-list.txt --spoof --multi --quiet --out out-file.txt --recursive

Description:
  This script supports two subcommands:

    1) dns  - perform standard DNS record lookups (A, AAAA, CNAME, etc.).
    2) mail - perform email-related lookups (MX, SPF, DMARC, DKIM, TLSA, etc.)
              and optionally attempt server validation or spoofing tests.

New Feature:
  --recursive   If set, any domain-like references found in record data (e.g., SPF strings)
                will be recursively queried in the same mode (DNS or Mail).
                Only subdomains (or the exact apex) of the primary domain(s) from the input 
                are considered for recursion, so IP addresses won't trigger recursion.
"""

import sys
import time
import re
import ipaddress
import socket
import ssl
import dns.resolver
import dns.exception
import dns.query
import dns.message
import dns.rdatatype
import dns.flags
import argparse
from typing import Union, List, Tuple, Dict, Set, Optional

# Import or define your record type metadata
from dns_record_types import DNS_RECORDS, CATEGORY_MAP, ORDERED_CATEGORIES

# Global file handle for logging
OUTPUT_FILE = None

# Global visited set to avoid infinite recursion
visited_domains: Set[str] = set()

# Global set of apex domains that recursion is allowed for
allowed_apex_domains: Set[str] = set()

###############################################################################
# Utility / Logging
###############################################################################

def ephemeral_print(message: str, end: str = "\r") -> None:
    """Write an ephemeral status update to stdout (not to OUTPUT_FILE)."""
    sys.stdout.write(message + end)
    sys.stdout.flush()

def status_update(message: str, end: str = "\n") -> None:
    """Write a status message to stdout only (not to the output file)."""
    sys.stdout.write(message + end)
    sys.stdout.flush()

def log_output(message: str, end: str = "\n") -> None:
    """Write a message to stdout and to OUTPUT_FILE if set."""
    sys.stdout.write(message + end)
    sys.stdout.flush()
    if OUTPUT_FILE is not None:
        OUTPUT_FILE.write(message + end)
        OUTPUT_FILE.flush()

NormalizedRecord = Tuple[str, str]  # (record_type, record_value)

###############################################################################
# Domain Extraction for Recursive Mode
###############################################################################

def ends_with_allowed_apex(candidate: str) -> bool:
    """
    Returns True if 'candidate' ends with any of the allowed_apex_domains
    or is exactly one of them. Everything else is excluded from recursion.
    Example:
      allowed_apex_domains = {"example.com"}
      Then "sub.example.com" or "example.com" is allowed. 
      "47.73.65.141" or "otherdomain.com" is not.
    """
    candidate = candidate.lower().rstrip(".")
    for apex in allowed_apex_domains:
        apex = apex.lower().rstrip(".")
        if candidate == apex:
            return True
        if candidate.endswith("." + apex):
            return True
    return False

def extract_potential_domains(record_text: str) -> List[str]:
    """
    Attempt to find domain-like strings in the given text.
    This is a simple regex that looks for typical domain patterns.
    Only return matches that end with an allowed apex domain.
    (IP addresses won't match because they don't have a top-level domain.)
    """
    pattern = re.compile(r"([a-zA-Z0-9-_]+\.[a-zA-Z0-9-.]+)", re.IGNORECASE)
    raw_candidates = pattern.findall(record_text)
    results = []
    for ref in raw_candidates:
        candidate = ref.lower().strip(".")
        # Filter out anything not in the allowed apex domain set
        if ends_with_allowed_apex(candidate):
            results.append(candidate)
    return results

###############################################################################
# DNS Query Functions
###############################################################################

def query_any_wildcard(domain: str, record_type: str) -> Union[List[NormalizedRecord], str]:
    query = dns.message.make_query(qname=domain, rdtype=dns.rdatatype.ANY, use_edns=True)
    query.flags |= dns.flags.RD
    query.use_edns(0, 0, 4096)
    resolver = dns.resolver.Resolver()
    if not resolver.nameservers:
        return "Error: No configured nameservers"
    nameserver = resolver.nameservers[0]
    try:
        response = dns.query.udp(query, nameserver, timeout=5)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, nameserver, timeout=5)
    except Exception as e:
        return f"Error: {e}"
    if not response.answer:
        return []
    records: List[NormalizedRecord] = []
    for rrset in response.answer:
        actual_type = dns.rdatatype.to_text(rrset.rdtype)
        for rr in rrset:
            records.append((actual_type, rr.to_text().strip()))
    return records

def query_dns_record(domain: str, rec_name: str, rec_id: int, rfc: str, desc: str) -> Union[List[NormalizedRecord], str]:
    """Resolve domain for the given record type. Fall back to numeric rec_id if textual fails."""
    if rec_name in ("ANY", "*"):
        return query_any_wildcard(domain, rec_name)
    try:
        answers = dns.resolver.resolve(domain, rec_name, lifetime=5)
        return [(rec_name, r.to_text().strip()) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        # fallback
        try:
            answers = dns.resolver.resolve(domain, rec_id, lifetime=5)
            return [(rec_name, r.to_text().strip()) for r in answers]
        except Exception as inner_e:
            return f"Error: {e} | Fallback Error: {inner_e}"
    except Exception as e:
        return f"Error: {e}"

def categorize_records(records: List[NormalizedRecord]) -> Dict[str, Set[NormalizedRecord]]:
    """Group results by the categories in dns_record_types.py."""
    grouped: Dict[str, Set[NormalizedRecord]] = {cat: set() for cat in ORDERED_CATEGORIES}
    grouped.setdefault("Other", set())
    for rec in records:
        rec_type, rec_text = rec
        found = False
        for cat in ORDERED_CATEGORIES:
            if cat == "Other":
                continue
            if rec_type in CATEGORY_MAP.get(cat, set()):
                grouped[cat].add(rec)
                found = True
                break
        if not found:
            grouped["Other"].add(rec)
    return grouped

def expand_cidr(cidr_str: str) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        return []

###############################################################################
# DNS Mode: Subcommand Handlers
###############################################################################

def process_dns_domain(domain: str, verbose: bool, recursive: bool) -> None:
    """
    Perform a DNS enumeration for one domain.
    If recursive is True, parse results for subdomains and re-query them 
    (only if they end with allowed apex domains).
    """
    visited_domains.add(domain.lower())

    header = f";; Processing domain: {domain} (DNS Mode)"
    log_output("\n" + "=" * len(header))
    log_output(header)
    log_output("=" * len(header) + "\n")
    log_output(f";; Started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
    log_output(f";; Querying {len(DNS_RECORDS)} DNS record types...\n")

    query_start = time.time()
    final_results: List[NormalizedRecord] = []
    any_found = False

    for rec_name, rec_id, rfc, desc in DNS_RECORDS:
        if verbose:
            log_output(f";; ------------------------------------------------------------")
            log_output(f";; Query: {rec_name} (Type {rec_id})")
            log_output(f";; Definition: {desc} [{rfc}]")
            log_output(f";; QUESTION SECTION:")
            log_output(f";;    {domain}. IN {rec_name}\n")

        result = query_dns_record(domain, rec_name, rec_id, rfc, desc)

        if verbose:
            log_output(";; ANSWER SECTION:")
            if isinstance(result, list) and result:
                for rec in result:
                    log_output(f";;    {rec[0]}: {rec[1]}")
            else:
                log_output(";;    No records found." if isinstance(result, list) else f";;    {result}")
            log_output("")

        if isinstance(result, list) and result:
            final_results.extend(result)
            if rec_name in ("ANY", "*"):
                any_found = True

    status_update(f"STATUS: Finished querying DNS records in {time.time() - query_start:.1f} seconds.")
    final_results = list(set(final_results))

    grouped = categorize_records(final_results)
    log_output(";; =================== Final Structured Output ===================")
    if any_found:
        log_output(";; ANY query responses were present.")
    else:
        log_output(";; No ANY query responses were found.")
    log_output(";; ------------------------------------------------------------\n")

    for cat in ORDERED_CATEGORIES:
        if cat == "Wildcard/ANY":
            continue
        if grouped.get(cat):
            log_output(f";; {cat} Records:")
            for rec in sorted(grouped[cat], key=lambda x: (x[0], x[1])):
                log_output(f"{rec[0]}: {rec[1]}")
            log_output("")

    # If recursive, parse subdomain references from final_results
    if recursive:
        discovered_subdomains: List[str] = []
        for (rectype, rectext) in final_results:
            possible_refs = extract_potential_domains(rectext)
            for ref in possible_refs:
                if ref not in visited_domains:
                    discovered_subdomains.append(ref)

        for subd in discovered_subdomains:
            process_dns_domain(subd, verbose, recursive)

###############################################################################
# Mail Mode: Subcommand Handlers
###############################################################################

def process_mail_records(records: List[NormalizedRecord], quiet: bool = False) -> Set[str]:
    mx_records = list({(r[0], r[1]) for r in records if r[0] == "MX"})
    spf_txts = list({(r[0], r[1]) for r in records if r[0] == "TXT" and "spf" in r[1].lower()})
    targets = set()

    if not quiet:
        log_output("========== MAIL-RELATED OUTPUT ==========")
        log_output("\n-- MX Records --")

    if mx_records:
        for rec_type, rec_text in mx_records:
            parts = rec_text.split()
            if len(parts) >= 2:
                pref = parts[0]
                mailhost = parts[1].rstrip(".")
                if not quiet:
                    log_output(f"MX: {pref} {mailhost}")
                try:
                    answers = dns.resolver.resolve(mailhost, "A", lifetime=5)
                    ips = {r.to_text().strip() for r in answers}
                    targets.update(ips)
                    if not quiet:
                        # Sort IP addresses numerically
                        for ip in sorted(ips, key=lambda ip: tuple(int(part) for part in ip.split('.'))):
                            log_output(f"    A: {ip}")
                except Exception as e:
                    if not quiet:
                        log_output(f"    [Error resolving A records for {mailhost}: {e}]")
    else:
        if not quiet:
            log_output("No MX records found.")

    if not quiet:
        log_output("\n-- SPF ip4 Entries --")

    if spf_txts:
        for rec_type, rec_text in spf_txts:
            txt = rec_text.strip('"')
            tokens = re.findall(r'ip4:([^\s"]+)', txt)
            for token in tokens:
                if "/" in token:
                    ips = expand_cidr(token)
                    targets.update(ips)
                    if not quiet:
                        for ip in sorted(ips, key=lambda ip: tuple(int(part) for part in ip.split('.'))):
                            log_output(f"ip4: {ip}")
                else:
                    targets.add(token)
                    if not quiet:
                        log_output(f"ip4: {token}")
    else:
        if not quiet:
            log_output("No SPF TXT records found.")

    return targets

def process_additional_mail_records(domain: str, quiet: bool = False) -> None:
    if not quiet:
        log_output("\n-- DMARC TXT Record --")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for r in answers:
            if not quiet:
                log_output(f"DMARC: {r.to_text().strip()}")
    except Exception:
        if not quiet:
            log_output("No DMARC record found.")

    if not quiet:
        log_output("\n-- DKIM TXT Records (at _domainkey) --")
    try:
        answers = dns.resolver.resolve(f"_domainkey.{domain}", "TXT", lifetime=5)
        for r in answers:
            if not quiet:
                log_output(f"DKIM: {r.to_text().strip()}")
    except Exception:
        if not quiet:
            log_output("No DKIM record found.")

    if not quiet:
        log_output("\n-- TLSA Records for SMTP (at _25._tcp.) --")
    try:
        answers = dns.resolver.resolve(f"_25._tcp.{domain}", "TLSA", lifetime=5)
        for r in answers:
            if not quiet:
                log_output(f"TLSA: {r.to_text().strip()}")
    except Exception:
        if not quiet:
            log_output(f"No TLSA record found at _25._tcp.{domain}")

    if not quiet:
        log_output("\n-- SRV Records for Mail Submission (_submission._tcp.) --")
    try:
        answers = dns.resolver.resolve(f"_submission._tcp.{domain}", "SRV", lifetime=5)
        for r in answers:
            if not quiet:
                log_output(f"SRV: {r.to_text().strip()}")
    except Exception:
        if not quiet:
            log_output(f"No SRV record found at _submission._tcp.{domain}")

def validate_server(ip: str, port: int, timeout: float = 5.0) -> Optional[str]:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if port == 465:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return None

def spoof_email(ip: str, port: int, domain: str, timeout: float = 5.0) -> Tuple[str, str]:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if port == 465:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        sock.sendall(b"EHLO test\r\n")
        sock.recv(1024)
        mail_from = f"MAIL FROM: <doesnotexist1@{domain}>\r\n"
        sock.sendall(mail_from.encode())
        sock.recv(1024)
        rcpt_to = f"RCPT TO: <doesnotexist2@{domain}>\r\n"
        sock.sendall(rcpt_to.encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        if not response.startswith("250"):
            sock.sendall(b"QUIT\r\n")
            sock.close()
            return ("REJECTED", banner)

        sock.sendall(b"DATA\r\n")
        sock.recv(1024)
        email_content = (
            f"From: doesnotexist1@{domain}\r\n"
            f"To: doesnotexist2@{domain}\r\n"
            "Subject: Spoof-Test\r\n"
            "\r\n"
            "This is a spoofing test!\r\n"
            ".\r\n"
        )
        sock.sendall(email_content.encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")

        sock.sendall(b"QUIT\r\n")
        sock.close()

        if response.startswith("250") or "queued" in response.lower():
            return ("SUCCESS", banner)
        else:
            return ("REJECTED", banner)
    except Exception:
        return ("ERROR", "")

def validate_mail_servers(targets: Set[str], quiet: bool = False) -> None:
    ports = [25, 465, 587, 2525]
    log_output(f"\n========== VALIDATING MAIL SERVERS (Total: {len(targets)} targets) ==========")
    # Use numeric sorting for IP addresses:
    for ip in sorted(targets, key=lambda ip: tuple(int(part) for part in ip.split('.'))):
        start_ip = time.time()
        port_lines = []
        for port in ports:
            banner = validate_server(ip, port)
            if banner:
                port_lines.append(f"Port {port}: {banner}")
        if port_lines and not quiet:
            log_output(f"\nValidating {ip}:")
            for line in port_lines:
                log_output(f"  {line}")
        if not quiet:
            status_update(f"STATUS: Finished validating {ip} in {time.time() - start_ip:.1f} seconds.")

def spoof_mail_servers(targets: Set[str], domain: str, quiet: bool,
                       multi_domains: Optional[List[str]] = None) -> None:
    """
    If multi_domains is provided, then for each target IP & port:
      - We first test the port with the first domain in multi_domains.
      - If it's "ERROR", skip that port altogether.
      - Otherwise, we test the entire multi_domains list on that port.
    """
    ports = [25, 465, 587, 2525]
    log_output(f"\n========== SPOOFING MAIL SERVERS (Total: {len(targets)} targets) ==========")
    # Sort IPs numerically:
    for ip in sorted(targets, key=lambda ip: tuple(int(part) for part in ip.split('.'))):
        start_ip = time.time()
        if quiet:
            ephemeral_print(f"STATUS: Spoofing {ip}... ", end="")
        else:
            log_output(f"\nSTATUS: Starting spoofing checks for {ip}...")

        port_lines = []
        for port in ports:
            if multi_domains:
                first_result, first_banner = spoof_email(ip, port, multi_domains[0])
                if first_result == "ERROR":
                    continue
                else:
                    for d in multi_domains:
                        result, banner = spoof_email(ip, port, d)
                        if result != "ERROR":
                            port_lines.append(f"Port {port} [{d}]: (SPOOF-CHECK: {result}) {banner}")
            else:
                result, banner = spoof_email(ip, port, domain)
                if result != "ERROR":
                    port_lines.append(f"Port {port}: (SPOOF-CHECK: {result}) {banner}")

        if port_lines:
            log_output(f"\nResults for {ip}:")
            for line in port_lines:
                log_output(f"  {line}")
        else:
            log_output(f"\nResults for {ip}: No open SMTP ports detected.")

        if quiet:
            ephemeral_print(f"STATUS: Finished spoofing {ip} in {time.time() - start_ip:.1f} seconds.", end="\n")
        else:
            log_output(f"STATUS: Finished spoofing {ip} in {time.time() - start_ip:.1f} seconds.")

def process_mail_domain(domain: str, verbose: bool, validate_mode: bool, spoof_mode: bool,
                        quiet: bool, multi_spoof_list: Optional[List[str]], recursive: bool = False) -> None:
    """
    Query DNS for mail records, gather targets, and optionally run validate/spoof checks.
    If recursive is True, parse discovered text for subdomains to re-check (only if they end with allowed apex domains).
    """
    visited_domains.add(domain.lower())

    header = f";; Processing domain: {domain} (MAIL Mode)"
    log_output("\n" + "=" * len(header))
    log_output(header)
    log_output("=" * len(header) + "\n")
    log_output(f";; Started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
    log_output(f";; Querying {len(DNS_RECORDS)} DNS record types...\n")

    query_start = time.time()
    final_results: List[NormalizedRecord] = []
    any_found = False

    for rec_name, rec_id, rfc, desc in DNS_RECORDS:
        if verbose and not quiet:
            log_output(f";; ------------------------------------------------------------")
            log_output(f";; Query: {rec_name} (Type {rec_id})")
            log_output(f";; Definition: {desc} [{rfc}]")
            log_output(f";; QUESTION SECTION:")
            log_output(f";;    {domain}. IN {rec_name}\n")

        result = query_dns_record(domain, rec_name, rec_id, rfc, desc)
        if verbose and not quiet:
            log_output(";; ANSWER SECTION:")
            if isinstance(result, list) and result:
                for rec in result:
                    log_output(f";;    {rec[0]}: {rec[1]}")
            else:
                log_output(";;    No records found." if isinstance(result, list) else f";;    {result}")
            log_output("")

        if isinstance(result, list) and result:
            final_results.extend(result)
            if rec_name in ("ANY", "*"):
                any_found = True

    status_update(f"STATUS: Finished querying DNS records in {time.time() - query_start:.1f} seconds.")
    final_results = list(set(final_results))

    if not quiet:
        log_output(";; ===========================================================")
        log_output(";; MAIL MODE OUTPUT")
        if any_found:
            log_output(";; ANY query responses were present.")
        else:
            log_output(";; No ANY query responses were found.")
        log_output(";; ===========================================================\n")
    else:
        log_output("MAIL MODE ENABLED (Quiet)")

    # Identify mail servers from MX / SPF
    targets = process_mail_records(final_results, quiet)
    process_additional_mail_records(domain, quiet)

    # Validate or Spoof?
    if spoof_mode:
        spoof_mail_servers(targets, domain, quiet, multi_spoof_list)
    elif validate_mode:
        validate_mail_servers(targets, quiet)

    if quiet:
        log_output(f"\nSTATUS: Total targets to be checked: {len(targets)}")

    # If recursive, parse subdomain references from final_results
    if recursive:
        discovered_subdomains: List[str] = []
        for (rectype, rectext) in final_results:
            possible_refs = extract_potential_domains(rectext)
            for ref in possible_refs:
                if ref not in visited_domains:
                    discovered_subdomains.append(ref)

        for subd in discovered_subdomains:
            process_mail_domain(subd, verbose, validate_mode, spoof_mode, quiet, multi_spoof_list, recursive=True)

###############################################################################
# Main (Subcommand Parsing)
###############################################################################

def main():
    global OUTPUT_FILE
    global allowed_apex_domains

    parser = argparse.ArgumentParser(
        description="DNS Digger v1.1 - Comprehensive DNS & Mail Record Lookup for offensive purposes",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Which subcommand to use? (dns or mail)")

    # -------------------------------------------------------------------------
    # DNS SUBCOMMAND
    # -------------------------------------------------------------------------
    dns_parser = subparsers.add_parser("dns", help="Perform standard DNS record lookups.")
    dns_group = dns_parser.add_mutually_exclusive_group(required=True)
    dns_group.add_argument("domain", nargs="?", help="Domain to query.")
    dns_group.add_argument("-iL", "--input-list", dest="input_list", help="File containing list of domains.")

    dns_parser.add_argument("--verbose", action="store_true", help="Show detailed DNS output for each query.")
    dns_parser.add_argument("--out", dest="outfile", help="File to write output to.")
    dns_parser.add_argument("--recursive", action="store_true", help="If set, parse discovered records for subdomains and re-query them.")

    # -------------------------------------------------------------------------
    # MAIL SUBCOMMAND
    # -------------------------------------------------------------------------
    mail_parser = subparsers.add_parser("mail", help="Perform mail-related DNS lookups & optional checks.")
    mail_group = mail_parser.add_mutually_exclusive_group(required=True)
    mail_group.add_argument("domain", nargs="?", help="Domain to query.")
    mail_group.add_argument("-iL", "--input-list", dest="input_list", help="File containing list of domains.")

    mail_parser.add_argument("--verbose", action="store_true", help="Show detailed mail output for each query.")
    mail_parser.add_argument("--validate", action="store_true", help="Validate mail servers on ports 25,465,587,2525.")
    mail_parser.add_argument("--spoof", action="store_true", help="Attempt to spoof an email from doesnotexist1@domain to doesnotexist2@domain.")
    mail_parser.add_argument("--multi", action="store_true", help="(Spoof mode) Re-test each discovered mail server for *all* domains.")
    mail_parser.add_argument("--quiet", action="store_true", help="Suppress detailed mail output; show only summary.")
    mail_parser.add_argument("--out", dest="outfile", help="File to write output to.")
    mail_parser.add_argument("--recursive", action="store_true", help="If set, parse discovered records for subdomains and re-query them.")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    # Open output file if requested
    if getattr(args, "outfile", None):
        try:
            OUTPUT_FILE = open(args.outfile, "w")
        except Exception as e:
            print(f"Error opening output file: {e}")
            sys.exit(1)

    verbose = getattr(args, "verbose", False)
    recursive = getattr(args, "recursive", False)

    all_input_domains: List[str] = []

    # -------------------------------------------------------------------------
    # DNS Subcommand Logic
    # -------------------------------------------------------------------------
    if args.subcommand == "dns":
        if args.input_list:
            try:
                with open(args.input_list, "r") as infile:
                    domain_lines = [line.strip() for line in infile if line.strip() and not line.strip().startswith("#")]
            except Exception as e:
                status_update(f"Error reading input list file: {e}")
                sys.exit(1)

            # Decorative output for loaded domains
            line = f";; Loaded {len(domain_lines)} domains from {args.input_list} for DNS checks."
            border = "=" * len(line)
            log_output("\n" + border)
            log_output(line)
            log_output(border + "\n")

            all_input_domains.extend(domain_lines)
        else:
            all_input_domains.append(args.domain)

        # Populate allowed_apex_domains from these input domains
        for d in all_input_domains:
            allowed_apex_domains.add(d.lower().rstrip("."))

        # Process them
        for dom in all_input_domains:
            d_l = dom.lower().strip(".")
            if d_l not in visited_domains:
                process_dns_domain(d_l, verbose, recursive)

    # -------------------------------------------------------------------------
    # MAIL Subcommand Logic
    # -------------------------------------------------------------------------
    elif args.subcommand == "mail":
        if args.input_list:
            try:
                with open(args.input_list, "r") as infile:
                    domain_lines = [line.strip() for line in infile if line.strip() and not line.strip().startswith("#")]
            except Exception as e:
                status_update(f"Error reading input list file: {e}")
                sys.exit(1)

            # Decorative output for loaded domains
            line = f";; Loaded {len(domain_lines)} domains from {args.input_list} for Mail checks."
            border = "=" * len(line)
            log_output("\n" + border)
            log_output(line)
            log_output(border + "\n")

            all_input_domains.extend(domain_lines)
        else:
            all_input_domains.append(args.domain)

        # Populate allowed_apex_domains
        for d in all_input_domains:
            allowed_apex_domains.add(d.lower().rstrip("."))

        for dom in all_input_domains:
            d_l = dom.lower().strip(".")
            if d_l not in visited_domains:
                multi_spoof_list = all_input_domains if getattr(args, "multi", False) else None
                process_mail_domain(
                    domain=d_l,
                    verbose=verbose,
                    validate_mode=getattr(args, "validate", False),
                    spoof_mode=getattr(args, "spoof", False),
                    quiet=getattr(args, "quiet", False),
                    multi_spoof_list=multi_spoof_list,
                    recursive=recursive
                )

    if OUTPUT_FILE is not None:
        OUTPUT_FILE.close()


if __name__ == "__main__":
    main()
