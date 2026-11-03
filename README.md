# IT-359-Penetration-Testing-Project

RUN TO START
(New Machine) sudo apt install -y nmap python3-nmap python3-requests
cd ~/IT-359-Penetration-Testing-Project
mkdir -p /tmp/shadow-ai-demo/ollama && : > /tmp/shadow-ai-demo/ollama/sample.gguf && printf 'DEMO_API_KEY=training-only-example\nauth_enabled=false\n' > /tmp/shadow-ai-demo/ollama/.env && chmod 644 /tmp/shadow-ai-demo/ollama/.env
python3 ShadowScanner/shadow-ai-internal/internal_scan.py --path /tmp/shadow-ai-demo --output ShadowScanner/internal_results.json
read -s -p "AI key: " AI_API_KEY && export AI_API_KEY
(Input API KEY)
cd ShadowScanner && python3 -m ReporterEngine.reporting_engine 127.0.0.1
