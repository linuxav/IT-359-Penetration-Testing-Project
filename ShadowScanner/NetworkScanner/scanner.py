import nmap
import json
import requests

class ShadowScan:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.signatures = { #TODO Add more ports to check
            11434 : "Ollama API",
            1234 : "LM Studio API",
            8000: "vLLM / Open WebUI / FastAPI",
            8080: "LocalAI / Llama.cpp"
        }

    def verify_endpoint(self, ip: str, port: int) -> str:
            """Verify probable endpoints"""
            try:
                if port == 11434:
                    # Ollama Verification TODO multiple services checks per port where applicable
                    response = requests.get(f"http://{ip}:{port}/", timeout=2)
                    if "Ollama is running" in response.text:
                        return "Verified Ollama Instance"
    
                elif port == 1234:
                    # LM Studio Verification
                    pass #TODO Add all services
    
            except Exception:
                pass 
    
            return "Unverified Service"

    def scan_target(self, target: str) -> dict:
        """Scans given target or target range for signatures."""
        # Convert keys (port numbers) from signatures dictionary into comma seperated list of strings
        ports_str = ",".join(map(str ,self.signatures.keys()))
        results = {}

        # nmap scan
        try:
            self.scanner.scan(hosts=target, ports=ports_str, arguments="-sV -Pn --open")
        except Exception as e:
            print(f"Scan Failed: {e}")
            return results

        # Process nmap data into readable output
        for host in self.scanner.all_hosts():
            host_data = {
                "hostname": self.scanner[host].hostname() or "Unknown",
                "state": self.scanner[host].state(),
                "detected_endpoints": []
            }

            for protocol in self.scanner[host].all_protocols():
                if protocol != "tcp":
                    continue

                ports = self.scanner[host][protocol].keys()
                for port in ports:
                    port_info = self.scanner[host][protocol][port]

                    if port_info.get("state") == "open":
                        verification_status = self.verify_endpoint(host, port)

                        endpoint_details = {
                            "port": port,
                            "probable_service": self.signatures.get(port, "Unknown"),
                            "verification": verification_status,
                            "name": port_info.get("name", ""),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extrainfo": port_info.get("extrainfo", "")
                        }
                        host_data["detected_endpoints"].append(endpoint_details)

            if host_data["detected_endpoints"]:
                results[host] = host_data
        return results

# Test ShadowScan against own device (empty dictionary is returned if no suspected ports are open)
if __name__ == "__main__":
    scanner = ShadowScan()
    target = "172.0.0.1"
    scan_output = scanner.scan_target(target)

    print(json.dumps(scan_output, indent=4))
