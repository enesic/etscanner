import asyncio
import socket
from typing import Dict, List

# Common subdomain prefixes for discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "imap", "blog",
    "dev", "staging", "api", "app", "admin", "portal", "vpn",
    "remote", "test", "beta", "demo", "store", "shop", "cdn",
    "cloud", "git", "gitlab", "jenkins", "ci", "cd", "jira",
    "wiki", "docs", "support", "help", "forum", "community",
    "status", "monitor", "grafana", "kibana", "elastic",
    "db", "database", "sql", "mysql", "postgres", "redis",
    "cache", "proxy", "gateway", "lb", "load", "node",
    "web", "web1", "web2", "app1", "app2", "srv", "server",
    "backup", "bak", "old", "new", "v2", "v3",
    "login", "auth", "sso", "oauth", "id", "identity",
    "media", "assets", "static", "img", "images", "video",
    "download", "upload", "files", "storage", "s3",
    "m", "mobile", "internal", "intranet", "extranet",
    "owa", "exchange", "autodiscover", "cpanel", "whm",
    "webdisk", "panel", "dashboard", "console",
    "staging2", "preprod", "uat", "qa", "sandbox",
]


class SubdomainDiscoverer:
    """Discover subdomains by performing DNS lookups against a wordlist.

    Uses Python's built-in ``socket.getaddrinfo`` to resolve each
    candidate subdomain. Runs lookups concurrently using asyncio.
    """

    def __init__(self, domain: str, max_concurrent: int = 50, timeout: float = 2.0):
        """
        Initialize the SubdomainDiscoverer.

        :param domain: Base domain to enumerate (e.g. 'example.com').
        :param max_concurrent: Maximum concurrent DNS lookups.
        :param timeout: Timeout per lookup in seconds.
        """
        self.domain = domain
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def _resolve(self, subdomain: str) -> Dict | None:
        """Attempt to resolve a single subdomain."""
        fqdn = f"{subdomain}.{self.domain}"
        async with self._semaphore:
            loop = asyncio.get_event_loop()
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._dns_lookup, fqdn),
                    timeout=self.timeout
                )
                if result:
                    return {"subdomain": fqdn, "ip": result}
            except (asyncio.TimeoutError, Exception):
                pass
        return None

    @staticmethod
    def _dns_lookup(fqdn: str) -> str | None:
        """Synchronous DNS resolution executed in a thread pool."""
        try:
            results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            if results:
                return results[0][4][0]  # First IPv4 address
        except socket.gaierror:
            pass
        except Exception:
            pass
        return None

    async def discover(self, custom_wordlist: List[str] = None) -> List[Dict]:
        """
        Run subdomain discovery against the target domain.

        :param custom_wordlist: Optional custom list of subdomain prefixes.
        :return: List of dictionaries with resolved subdomains and IPs.
        """
        wordlist = custom_wordlist or COMMON_SUBDOMAINS

        tasks = [asyncio.create_task(self._resolve(sub)) for sub in wordlist]
        raw_results = await asyncio.gather(*tasks)

        # Filter out None results and sort by subdomain
        found = [r for r in raw_results if r is not None]
        found.sort(key=lambda x: x["subdomain"])

        return found
