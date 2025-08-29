from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
import json
from datetime import datetime


def save_network_analysis(app_name, domains, requests):
    network_data = {
        'app_name': app_name,
        'domains_contacted': list(domains),
        'total_requests': len(requests),
        'analysis_date': datetime.now().isoformat()
    }

    with open(f"{app_name}_network_analysis.json", 'w') as f:
        json.dump(network_data, f, indent=2)

    return network_data


def analyze_traffic(filename):
    domains = set()
    requests = []

    with open(filename, "rb") as logfile:
        freader = io.FlowReader(logfile)
        try:
            for flow in freader.stream():
                domain = flow.request.pretty_host
                url = f"{domain}{flow.request.path}"
                domains.add(domain)
                requests.append({
                    'domain': domain,
                    'url': url,
                    'method': flow.request.method,
                    'timestamp': str(flow.timestamp_start)
                })
        except FlowReadException as e:
            print(f"Error reading flow: {e}")

    print(f"\n=== NETWORK ANALYSIS ===")
    print(f"Total requests: {len(requests)}")
    print(f"Unique domains contacted: {len(domains)}")

    print(f"\nDomains contacted:")
    for domain in sorted(domains):
        count = sum(1 for r in requests if r['domain'] == domain)
        print(f"  {domain} ({count} requests)")


    network_data = save_network_analysis("Calculator", domains, requests)
    print(f"\nNetwork analysis saved to: Calculator_network_analysis.json")

    return requests


#RUN NOW yep
if __name__ == "__main__":
    analyze_traffic("calculator_traffic.flow")