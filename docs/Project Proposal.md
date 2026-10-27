**Shadow AI Vulnerability Scanner** 

Scans a target network for poorly secured **local AI model deployments** ("shadow AI"). Examples could include: Ollama, LM Studio, text-generation-webui, llama.cpp server, vLLM, or LocalAI instances that employees have spun up without IT approval, often left with no authentication.

**What's deployed & how:**

- **Discovery module:** Scans the network for known default ports/API signatures of common local-AI tools (Ollama on 11434, text-generation-webui on 5000, LM Studio on 1234, vLLM on 8000). 

  - Uses banner grabbing and known API endpoints to fingerprint what's running.

**Internal Scan Module:** Searches local machine files for AI specific files to find and document unauthorized/insecure AI models running on or connected to the machine. Seaches for common AI file types (.gguf, .safetensors, .ckpt, etc.), process names (ollama, lmstudio, anythingllm, etc.), folders (.cach/huggingface, LM Studio, AnythingLLM), config files, and API Keys.

- **Test-bed requirement:** Since a real network likely won't have live shadow AI to test against, the project needs its own controlled test environment — a few intentionally-deployed local AI instances (possibly Ollama) configured with no-auth/default settings, standing in for a "vulnerable" shadow deployment. 

- **Attack module:** Sends a library of jailbreak/prompt-injection payloads to any discovered endpoint, attempting to get the model to confirm it's active and/or leak information about its host (hostname, OS, files, network config) 

- **Reporting engine**: Logs each attack attempt, the payload used, and the model's response, then scores the severity and outputs a report. Uses AI Agent to format and add additional explanations as needed in a human readable format.

**Coding details:**

- Language: Python

- Network discovery: python-nmap or raw socket scanning for open ports + service fingerprinting

- API interaction: requests/httpx to talk to each tool's REST API

- Payload set: a curated library of known jailbreak prompts (DAN-style, roleplay-based, instruction-override) stored as JSON/YAML for easy expansion

- Reporting: results rendered to HTML/PDF via Jinja2 templates, or exported as JSON for later ingestion

- Interface: CLI tool for MVP (e.g., python scanner.py --subnet 10.0.0.0/24)