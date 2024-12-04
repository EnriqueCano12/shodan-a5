import requests
import time
import ipaddress
import os
from typing import List, Dict, Union, Optional
from openai import OpenAI
import json

class ShodanQueryOrchestrator:
    def __init__(self):
        """Initialise the orchestrator with OpenAI API key from environment."""
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.api_base = "https://internetdb.shodan.io"
        self.last_request_time = 0
        
    def _enforce_rate_limit(self) -> None:
        """
        Enforces a 1-second delay between API requests.
        No parameters required.
        Returns: None
        Example: self._enforce_rate_limit()
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < 1.0:  # 1 second delay
            time.sleep(1.0 - time_since_last_request)
        self.last_request_time = time.time()

    def _expand_ip_range(self, ip_range: str) -> List[str]:
        """
        Expands an IP range into individual IP addresses.
        Parameters:
            ip_range (str): IP range in CIDR notation (e.g., '192.168.1.0/24') or single IP
        Returns:
            List[str]: List of individual IP addresses
        Example: self._expand_ip_range('192.168.1.0/30') returns ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
        """
        try:
            return [str(ip) for ip in ipaddress.ip_network(ip_range, strict=False)]
        except ValueError:
            return [ip_range]

    def _query_shodandb(self, ip: str) -> Optional[Dict]:
        """
        Queries the Shodan InternetDB API for a single IP.
        Parameters:
            ip (str): Single IP address to query
        Returns:
            Optional[Dict]: JSON response with format:
            {
                "cpes": ["string"],
                "hostnames": ["string"],
                "ip": "string",
                "ports": [int],
                "tags": ["string"],
                "vulns": ["string"]
            }
            Returns None if request fails
        Example: self._query_shodandb('8.8.8.8')
        """
        try:
            response = requests.get(
                f"{self.api_base}/{ip}",
                headers={'accept': 'application/json'}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except requests.RequestException:
            return None

        SYSTEM_PROMPT = """You are a cybersecurity analyst using Shodan's InternetDB API. You have these tools:

AVAILABLE TOOLS:
- _expand_ip_range(ip_range: str): Expands CIDR notation to IP list
- _query_shodandb(ip: str): Gets {cpes, hostnames, ip, ports, tags, vulns}
- _enforce_rate_limit(): Must call before each _query_shodandb

OUTPUT RULES:
1. CRITICAL ISSUES 
- List vulnerabilities with CVEs first
- Flag dangerous open ports (21,22,23,80,443,3389)
- Highlight unusual services or configurations

2. EXPOSURE SUMMARY
- Count of exposed IPs
- Open ports statistics
- Common services detected

3. DETAILED FINDINGS
[Only include if relevant data exists]
- Vulnerable IPs: List specific IPs and their CVEs
- Port Exposure: Group IPs by open ports
- Service Analysis: List unusual or risky services
- Infrastructure: Note interesting hostnames or CPEs

FORMAT:
[critical issues found? start with "ALERT:"]
[no issues? start with "SCAN COMPLETE:"]

Examples:

For vulnerability query:
ALERT: Found 2 vulnerable IPs
- 192.168.1.2: CVE-2023-1234 (RCE)
- 192.168.1.3: Multiple vulns (CVE-2023-...)
Recommendation: Immediate patching required

For port scan:
SCAN COMPLETE: 5 IPs analyzed
- 3 IPs expose port 80 (192.168.1.2-4)
- 1 IP exposes telnet (192.168.1.5)
Recommendation: Disable telnet, verify web exposure

For security summary:
ALERT: Multiple exposures found
- 2 critical CVEs detected
- 3 IPs with excessive port exposure
- Unusual service: tftp on 192.168.1.4
Recommendation: Security audit needed"""

    def process_query(self, user_query: str, ip_input: str) -> str:
        """Process a natural language query about IP(s)."""
        # Define available tools
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "_enforce_rate_limit",
                    "description": self._enforce_rate_limit.__doc__,
                    "parameters": {"type": "object", "properties": {}}
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "_expand_ip_range",
                    "description": self._expand_ip_range.__doc__,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip_range": {"type": "string"}
                        },
                        "required": ["ip_range"],
                        "additionalProperties": False
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "_query_shodandb",
                    "description": self._query_shodandb.__doc__,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip": {"type": "string"}
                        },
                        "required": ["ip"],
                        "additionalProperties": False
                    }
                }
            }
        ]

        # Get LLM's analysis plan and execute it
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system", 
                    "content": [{"type": "text", "text": self.SYSTEM_PROMPT}]
                },
                {
                    "role": "user", 
                    "content": [{
                        "type": "text", 
                        "text": f"""
                        Process this query with the available functions:
                        Query: {user_query}
                        IP Input: {ip_input}
                        
                        Think step by step about how to handle this query, then execute your plan.
                        Include your reasoning and the function calls you would make.
                        """
                    }]
                }
            ],
            tools=tools
        )

        # Execute the LLM's plan
        tool_calls = response.choices[0].message.tool_calls
        results = {}
        
        if tool_calls:
            for call in tool_calls:
                call_args = json.loads(call.function.arguments)
                if call.function.name == "_expand_ip_range":
                    results["ips"] = self._expand_ip_range(call_args["ip_range"])
                elif call.function.name == "_query_shodandb":
                    self._enforce_rate_limit()  # Always enforce rate limit before API call
                    ip = call_args["ip"]
                    results[ip] = self._query_shodandb(ip)

        # Get LLM's analysis of the results
        analysis_response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system", 
                    "content": [{"type": "text", "text": self.SYSTEM_PROMPT}]
                },
                {
                    "role": "user", 
                    "content": [{
                        "type": "text", 
                        "text": f"""
                        Analyse these results and answer the original query:
                        Query: {user_query}
                        Results: {json.dumps(results)}
                        """
                    }]
                }
            ]
        )

        return analysis_response.choices[0].message.content

def main():
    """Example usage of the ShodanQueryOrchestrator"""
    orchestrator = ShodanQueryOrchestrator()
    
    # Example queries to test the orchestrator
    queries = [
        ("What vulnerabilities exist in this IP?", "192.168.1.1"),
        ("Which IPs in this range have open port 80?", "192.168.1.0/29"),
        ("Summarise the security findings for these IPs", "192.168.1.0/28")
    ]
    
    for query, ip_range in queries:
        response = orchestrator.process_query(query, ip_range)
        print(f"\nQuery: {query}")
        print(f"IP Range: {ip_range}")
        print(f"Response: {response}")

if __name__ == "__main__":
    main()
