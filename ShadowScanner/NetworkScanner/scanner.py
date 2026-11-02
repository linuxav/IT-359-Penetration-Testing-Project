import nmap
import json
import requests

class ShadowScan:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.signatures = {
            1234 : ("LM Studio API", "/v1/models", None),
            1337 : ("Jan AI", "/v1/models", None),
            3000 : ("Open WebUI", "/", "open-webui"),
            5000 : ("OobaGooba API", "/v1/models", None),
            5001 : ("KoboldCPP", "/api/v1/model", None),
            6333 : ("Qdrant Vector DB", "/readyz", "qdrant"),
            7860 : ("OobaGooba Gradio Web UI / Stable Diffusion", "/", "gradio"),
            8000 : ("vLLM / Open WebUI / FastAPI", "/v1/models", None),
            8080 : ("LocalAI / Llama.cpp / Open WebUI", "/v1/models", None),
            9000 : ("Hugging Face TGI", "/info", "model_id"),
            10000: ("Moshi Voice-to-Voice AI", "/", "moshi"),
            10012: ("Bark TTS Engine", "/", "bark"),
            11434: ("Ollama API", "/", "ollama is running"),
            19530: ("Milvus Vector DB", "/v1/vector/collections", None)
        }

    def verify_endpoint(self, ip: str, port: int) -> str:
            """Verify probable endpoints"""
            if port not in self.signatures:
                return "Unverified Service"

            service_name, endpoint, fingerprint = self.signatures[port]
            url = f"http://{ip}:{port}{endpoint}"
            
            try:
                response = requests.get(url, timeout=2, allow_redirects=True)

                if response.status_code == 200:
                    if not fingerprint:
                        return f"{service_name} Verified"
                    if fingerprint.lower() in response.text.lower():
                        return f"{service_name} Verified"
                    
                elif response.status_code in [401, 403, 405]:
                    return f"{service_name} Possible (Auth Required / Method Not Allowed)"
    
            except requests.exceptions.RequestException:
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

                        sig_tuple = self.signatures.get(port)
                        service_name = sig_tuple[0] if sig_tuple else "Unkown AI Port"

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
    target = "127.0.0.1"
    scan_output = scanner.scan_target(target)

    print(json.dumps(scan_output, indent=4))
