# DNS Digger v1.1

**DNS Digger** is a comprehensive DNS and Mail Record Lookup tool designed for offensive security assessments and penetration testing. It automates the enumeration of DNS records and creatively identifies mail servers, while also testing them for vulnerabilities such as spoofing. This tool is useful for mapping target infrastructures and discovering misconfigurations in email services.

> **Note on Wildcard Lookups:**  
> Modern DNS servers often disable or restrict wildcard lookups (e.g. using `*`) to mitigate DNS amplification attacks and reduce performance overhead. Consequently, wildcard queries may return limited or no data, so DNS Digger focuses on other record types to deliver valuable insights.

---

## Features

- **DNS Record Enumeration:**  
  Retrieve a wide range of DNS records (A, AAAA, CNAME, etc.) to gain insight into a target’s network structure.

- **Mail Record Enumeration:**  
  Identify email-related records (MX, SPF, DMARC, DKIM, TLSA, etc.) to locate mail servers for a given domain.

- **SMTP Server Validation:**  
  Connect to discovered mail servers on common SMTP ports (25, 465, 587, 2525) and capture banner information to assess their configuration.

- **Spoofing Test:**  
  Simulate SMTP sessions to determine if mail servers are vulnerable to spoofing attacks.

- **Bulk Domain Support:**  
  Process a single domain or a list of domains (via an input file), with a decorative banner showing the number of domains loaded.

- **Recursive Mode:**  
  When `--recursive` is enabled, any newly discovered subdomains (within the same apex domain(s)) are automatically re‐queried in the current mode (DNS or Mail). This can reveal additional mail servers or DNS entries not visible at first glance.

  > **Performance Note:** Recursive lookups in **Mail** mode can be **time‐consuming**, since each newly discovered subdomain can be probed for mail records and spoof/validation checks. Use with caution on large domain sets.

- **Subcommand Interface:**  
  - **`dns` Subcommand:** For standard DNS record lookups.
  - **`mail` Subcommand:** For mail‐related lookups and vulnerability tests.

---

## Installation Summary

1. Clone the repository:
    ```bash
    git clone https://github.com/0xB455/dns-digger.git
    cd dns-digger
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the tool in either DNS or Mail mode using the examples below (or with your own parameters).

---

## Usage

DNS Digger uses a subcommand interface with two main modes: **DNS** and **Mail**.

### DNS Mode

Perform standard DNS record lookups for a single domain or multiple domains from a file.

**Example 1: Single Domain**

```bash
python3 dns-digger.py dns example.com --verbose
```

This command queries a comprehensive set of DNS records for `example.com` and shows detailed output.

**Example 2: Bulk Domain Lookups**

```bash
python3 dns-digger.py dns -iL domainlist.txt
```

When using `-iL`, the tool displays a decorative banner indicating the number of domains loaded before processing them.

**Example 3: Recursive DNS Lookups
```bash
python3 dns-digger.py dns example.com --recursive
```

Any subdomains of `example.com` discovered in DNS records will also be queried automatically. This helps reveal deeper DNS structures not visible from a single pass.

### Mail Mode

Perform email-related lookups and tests for a single domain or multiple domains.

**Example 1: Single Domain with Server Validation**

```bash
python3 dns-digger.py mail example.com --validate
```

This command retrieves mail-related DNS records for `example.com` and validates discovered mail servers on common SMTP ports.

**Example 2: Single Domain with Spoofing Test (Verbose)**

```bash
python3 dns-digger.py mail example.com --spoof --verbose
```

This runs a spoofing test against the mail servers for `example.com`, displaying detailed output.

**Example 3: Bulk Mail Lookups with Spoofing**

```bash
python3 dns-digger.py mail -iL input-list.txt --spoof --multi --quiet --out results.txt
```

- `-iL input-list.txt`: Loads multiple domains from the file.
- `--spoof`: Runs a spoofing test.
- `--multi`: In spoof mode, re-tests each discovered mail server for all domains loaded.
- `--quiet`: Suppresses detailed output (shows summary and status updates only).
- `--out results.txt`: Writes the output to `results.txt`.

After reading the input list, DNS Digger will display a decorative banner showing how many domains were loaded, then process each domain accordingly.

**Example 4: Recursive Mail Lookups
```bash
python3 dns-digger.py mail -iL input-list.txt --spoof --recursive
```

- Discovers subdomains for all apex domains in input-list.txt.
- Checks mail‐related records (MX, SPF, DMARC, etc.) for each subdomain.
- Attempts spoof/validation on each newly discovered subdomain’s mail servers.
- **Caution:** Can result in long runtimes if the domain list is large or if many subdomains exist, as each subdomain may trigger multiple DNS queries and SMTP checks.

---

## How It Works

1. **DNS Record Enumeration:**  
   DNS Digger queries a comprehensive set of DNS record types (defined in `dns_record_types.py`) to provide a full picture of the target’s DNS infrastructure.

2. **Mail Record Identification:**  
   In mail mode, the tool focuses on email-specific DNS records (such as MX and SPF) to discover the mail servers used by the target.

3. **SMTP Validation & Spoofing Test:**  
   - **Validation:** Connects to identified mail servers on common SMTP ports to retrieve banner information and verify connectivity.
   - **Spoofing Test:** Simulates an SMTP session using non-existent email addresses to see if the server will accept spoofed messages, revealing potential vulnerabilities.

4. **Recursive Subdomain Lookups (Optional):
   When `--recursive` is enabled, any discovered subdomain references that match the apex domain(s) are re‐queried. This is true for both DNS and Mail subcommands, allowing you to reveal deeper tiers of DNS records and mail servers not visible from a single pass.

This dual approach not only maps out DNS and mail infrastructures but also creatively probes for misconfigurations and vulnerabilities.

---

## Why Use DNS Digger?

DNS Digger is especially useful for penetration testers and offensive security professionals because it:

- **Automates Reconnaissance:** Quickly gathers a broad range of DNS and mail data across single or multiple domains.
- **Uncovers Vulnerabilities:** Identifies misconfigured or vulnerable mail servers that may be exploited for spoofing attacks based on DNS intel.
- **Enhances Situational Awareness:** Provides a deeper understanding of the target’s network and email infrastructure.
- **Saves Time:** Integrates DNS and mail analysis into a single tool, streamlining the reconnaissance phase of your assessments.

---

## Requirements

- **Python 3.x**
- **dnspython** (installed via `requirements.txt`)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*Happy Digin'!*
```
