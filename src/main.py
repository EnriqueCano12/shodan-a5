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

    SYSTEM_PROMPT = """You are an AI assistant with access to the following functions for analysing IP security data:

1. _enforce_rate_limit()
   - Enforces 1-second delay between API requests
   - No parameters needed
   - Returns None
   - Must be called before each API request

2. _expand_ip_range(ip_range: str) -> List[str]
   - Converts IP range to list of individual IPs
   - Parameter: ip_range (CIDR notation or single IP)
   - Returns list of IP strings
   - Example: '192.168.1.0/30' → ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']

3. _query_shodandb(ip: str) -> Optional[Dict]
   - Queries Shodan API for single IP
   - Parameter: ip (single IP address)
   - Returns JSON with format:
     {
       "cpes": ["string"],
       "hostnames": ["string"],
       "ip": "string",
       "ports": [int],
       "tags": ["string"],
       "vulns": ["string"]
     }
   - Returns None if request fails

Your task is to:
1. Process natural language queries about IP security
2. Use the available functions to gather necessary data
3. Remember to enforce rate limits
4. Analyse the data and provide relevant insights

Always think step by step about:
1. Whether you need to expand an IP range
2. How to handle rate limits between requests
3. How to process and analyse the returned data
4. How to format the response based on the user's question

"""

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
