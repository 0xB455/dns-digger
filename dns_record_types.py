# dns_record_types.py
#
# This file defines a comprehensive list of DNS record types and
# categorizes them for structured output.
#
# Each record type is defined as a tuple:
# (record type name, type id, defining RFC(s), description)

DNS_RECORDS = [
    # Active Resource Records
    ("A", 1, "RFC 1035", "Address record: Returns a 32-bit IPv4 address."),
    ("AAAA", 28, "RFC 3596", "IPv6 address record: Returns a 128-bit IPv6 address."),
    ("CNAME", 5, "RFC 1035", "Canonical name record: Alias of one name to another."),
    ("MX", 15, "RFC 1035/7505", "Mail exchange record: Lists mail servers for a domain."),
    ("NS", 2, "RFC 1035", "Name server record: Delegates a zone to authoritative name servers."),
    ("SOA", 6, "RFC 1035/2308", "Start of Authority record: Contains administrative zone info."),
    ("TXT", 16, "RFC 1035", "Text record: Carries human- and machine-readable text data."),
    ("PTR", 12, "RFC 1035", "Pointer record: Maps an IP address to a canonical name (reverse DNS)."),
    ("DNAME", 39, "RFC 6672", "Delegation Name record: Alias for an entire subtree of the domain name space."),

    # DNSSEC / Security Related
    ("DNSKEY", 48, "RFC 4034", "DNS Key record: Contains the public key for DNSSEC."),
    ("DS", 43, "RFC 4034", "Delegation signer: Identifies the DNSSEC signing key for a delegated zone."),
    ("RRSIG", 46, "RFC 4034", "DNSSEC signature: Contains signatures for DNSSEC-secured records."),
    ("NSEC", 47, "RFC 4034", "Next Secure record: Proves nonexistence of a name in DNSSEC."),
    ("NSEC3", 50, "RFC 5155", "Next Secure record v3: Extension for DNSSEC nonexistence proofs."),
    ("NSEC3PARAM", 51, "RFC 5155", "NSEC3 parameters: Provides parameters for NSEC3."),
    ("CAA", 257, "RFC 6844", "Certification Authority Authorization: Constrains acceptable CAs."),
    ("CDNSKEY", 60, "RFC 7344", "Child DNSKEY: Child copy of DNSKEY for transfer to parent."),
    ("CDS", 59, "RFC 7344", "Child DS: Child copy of DS for transfer to parent."),
    ("TLSA", 52, "RFC 6698", "TLSA certificate association: Binds a TLS server certificate or key to a domain."),
    ("TSIG", 250, "RFC 2845", "Transaction Signature: Authenticates dynamic updates/responses."),
    ("ZONEMD", 63, "RFC 8976", "Zone Message Digest: Provides a digest over zone data."),
    ("DLV", 32769, "RFC 4431", "DNSSEC Lookaside Validation record: Provides an alternative trust anchor mechanism for DNSSEC."),

    # Service Records
    ("SRV", 33, "RFC 2782", "Service locator: Specifies the location of servers for specific services."),
    ("NAPTR", 35, "RFC 3403", "Naming Authority Pointer: Enables regex-based rewriting of domain names."),
    ("URI", 256, "RFC 7553", "Uniform Resource Identifier: Publishes URIs associated with a domain."),
    ("SVCB", 64, "RFC 9460", "Service Binding: Improves performance for resource resolution."),
    ("CSYNC", 62, "RFC 7477", "Child-to-Parent Synchronization: Synchronizes child and parent DNS zones."),
    ("DHCID", 49, "RFC 4701", "DHCP Identifier: Used with the DHCP FQDN option."),
    ("HTTPS", 65, "RFC 9460", "HTTPS Binding: Optimizes resolution for HTTPS resources."),
    ("OPT", 41, "RFC 6891", "Option record: Supports EDNS options."),
    ("TKEY", 249, "RFC 2930", "Transaction Key record: Used for establishing shared secret keys for DNS transactions."),

    # Miscellaneous / Other
    ("HINFO", 13, "RFC 8482", "Host Information: Provides CPU and OS info of a host."),
    ("HIP", 55, "RFC 8005", "Host Identity Protocol: Separates host identity from locator."),
    ("IPSECKEY", 45, "RFC 4025", "IPsec Key: Used with IPsec for keying material."),
    ("KX", 36, "RFC 2230", "Key Exchanger record: Identifies a key management agent for a domain."),
    ("LOC", 29, "RFC 1876", "Location record: Specifies a geographical location for a domain."),
    ("OPENPGPKEY", 61, "RFC 7929", "OpenPGP public key record: Publishes OpenPGP keys for a domain."),
    ("RP", 17, "RFC 1183", "Responsible Person: Provides contact information for a domain."),
    ("SMIMEA", 53, "RFC 8162", "S/MIME certificate association: Associates an S/MIME certificate with a domain."),
    ("AFSDB", 18, "RFC 1183", "AFS database record: Specifies a server for AFS or DCE cell."),
    ("CERT", 37, "RFC 4398", "Certificate record: Stores certificates or related certificate revocation lists."),
    ("APL", 42, "RFC 3123", "Address Prefix List: Specifies address prefixes with masks."),
    ("SSHFP", 44, "RFC 4255", "SSH Fingerprint record: Associates SSH public keys with host names."),
    ("EUI48", 108, "RFC 7043", "EUI-48 address record: Stores a 48-bit Extended Unique Identifier (EUI-48)."),
    ("EUI64", 109, "RFC 7043", "EUI-64 address record: Stores a 64-bit Extended Unique Identifier (EUI-64)."),

    # Zone Transfer
    ("AXFR", 252, "RFC 1035", "Authoritative Zone Transfer: Transfers an entire zone file."),
    ("IXFR", 251, "RFC 1996", "Incremental Zone Transfer: Transfers only changed parts of a zone."),

    # Wildcard / ANY (pseudo-records)
    ("ANY", 255, "RFC 8482", "ANY query: Returns all available records for a domain (may be limited)."),
    ("*", 255, "RFC 1035", "Wildcard record: Returns all records matching a wildcard query."),

    # Obsolete / Deprecated (for pentesting purposes)
    ("MD", 3, "RFC 883/973", "Obsolete mail destination record; replaced by MX."),
    ("MF", 4, "RFC 883", "Obsolete mail forwarder record; replaced by MX."),
    ("MAILA", 254, "Obsolete", "Obsolete query type for mail routing."),
    ("MB", 7, "RFC 883", "Obsolete mailbox record for subscriber mailing lists."),
    ("MG", 8, "RFC 883", "Obsolete mail group record."),
    ("MR", 9, "RFC 883", "Obsolete mail rename record."),
    ("MINFO", 14, "RFC 883", "Obsolete mail information record."),
    ("MAILB", 253, "Obsolete", "Obsolete query type for mail routing."),
    ("WKS", 11, "RFC 883/1035", "Obsolete well-known services record."),
    ("NB", 32, "RFC 1002", "Obsolete NetBIOS record."),
    ("NBSTAT", 33, "Obsolete", "Obsolete NetBIOS status record."),
    ("NULL", 10, "RFC 883/1035", "Obsolete null record."),
    ("A6", 38, "RFC 2874/6563", "Obsolete IPv6 address record; replaced by AAAA."),
    ("NXT", 30, "RFC 2065/3755", "Obsolete DNSSEC record; replaced by NSEC."),
    ("X25", 19, "Obsolete", "Obsolete X.25 address record."),
    ("ISDN", 20, "Obsolete", "Obsolete ISDN record."),
    ("RT", 21, "Obsolete", "Obsolete route-through record."),
    ("NSAP", 22, "RFC 1706", "Obsolete NSAP address record."),
    ("NSAP-PTR", 23, "Obsolete", "Obsolete NSAP pointer record."),
    ("PX", 26, "RFC 2163", "Obsolete mapping record for X.400/RFC 2163."),
    ("EID", 31, "N/A", "Experimental record for endpoint identifier."),
    ("NIMLOC", 32, "Obsolete", "Obsolete network information location record."),
    ("ATMA", 34, "Obsolete", "Obsolete record for ATM addresses."),
    ("SINK", 40, "Obsolete", "Obsolete record defined in the Kitchen Sink draft."),
    ("GPOS", 27, "RFC 1712", "Obsolete geographical position record."),
    ("UINFO", 100, "Obsolete", "Obsolete user information record."),
    ("UID", 101, "Obsolete", "Obsolete user identifier record."),
    ("GID", 102, "Obsolete", "Obsolete group identifier record."),
    ("UNSPEC", 103, "Obsolete", "Obsolete unspecified record."),
    ("SPF", 99, "RFC 4408/7208", "Obsolete SPF record; use TXT record instead."),
    ("NINFO", 56, "Obsolete", "Obsolete zone status information record."),
    ("RKEY", 57, "Obsolete", "Obsolete record for NAPTR encryption."),
    ("TALINK", 58, "Obsolete", "Obsolete record for DNSSEC trust anchor history."),
    ("NID", 104, "RFC 6742", "Obsolete/experimental node identifier record."),
    ("L32", 105, "Obsolete", "Obsolete 32-bit Locator record."),
    ("L64", 106, "Obsolete", "Obsolete 64-bit Locator record."),
    ("LP", 107, "Obsolete", "Obsolete Locator Pointer record."),
    ("DOA", 259, "Obsolete", "Obsolete DNS-based Origin Authentication record."),
    ("SIG", 24, "Obsolete", "Obsolete signature record; replaced by RRSIG."),
    ("KEY", 25, "Obsolete", "Obsolete key record; replaced by DNSKEY."),
]

# Category mapping for output grouping.
CATEGORY_MAP = {
    "Wildcard/ANY": {"ANY", "*"},
    "Basic": {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR", "DNAME"},
    "DNSSEC": {"DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CAA",
               "CDNSKEY", "CDS", "TLSA", "TSIG", "ZONEMD", "DLV"},
    "Service": {"SRV", "NAPTR", "URI", "SVCB", "CSYNC", "DHCID", "HTTPS", "OPT", "TKEY"},
    "Zone Transfer": {"AXFR", "IXFR"},
    "Obsolete": {"MD", "MF", "MAILA", "MB", "MG", "MR", "MINFO", "MAILB", "WKS", "NB",
                 "NBSTAT", "NULL", "A6", "NXT", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR",
                 "PX", "EID", "NIMLOC", "ATMA", "SINK", "GPOS", "UINFO", "UID", "GID",
                 "UNSPEC", "SPF", "NINFO", "RKEY", "TALINK", "NID", "L32", "L64", "LP",
                 "DOA", "SIG", "KEY"},
    "Misc": {"AFSDB", "APL", "CERT", "HINFO", "HIP", "IPSECKEY", "KX", "LOC",
             "OPENPGPKEY", "RP", "SMIMEA", "SSHFP", "EUI48", "EUI64"},
}
ORDERED_CATEGORIES = ["Wildcard/ANY", "Basic", "DNSSEC", "Service", "Zone Transfer", "Obsolete", "Misc", "Other"]
