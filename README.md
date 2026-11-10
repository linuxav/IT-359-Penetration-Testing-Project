# IT-359-Penetration-Testing-Project

## Dependencies

Sudo apt install nmap requests

## How to Run

cd \~/IT-359-Penetration-Testing-Project

read \-s \-p "AI key: " AI\_API\_KEY && export AI\_API\_KEY

mkdir \-p /tmp/shadow-ai-demo/ollama && : \> /tmp/shadow-ai-demo/ollama/sample.gguf && printf 'DEMO\_API\_KEY=training-only-example\\nauth\_enabled=false\\n' \> /tmp/shadow-ai-demo/ollama/.env && chmod 644 /tmp/shadow-ai-demo/ollama/.env

python3 ShadowScanner/shadow-ai-internal/internal\_scan.py \--path /tmp/shadow-ai-demo \--output ShadowScanner/internal\_results.json

cd ShadowScanner && python3 \-m ReporterEngine.reporting\_engine 127.0.0.1
