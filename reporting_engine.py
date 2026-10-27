
import json       
# this reads and writes JSON files
import sys        
# this prints warnings to stderr
import requests   
# this sends HTTP requests to the AI server

AI_URL = "http://sushi.it.ilstu.edu:8080/v1/chat/completions"  
# This is the AI endpoint to call
AI_KEY = "PUT-YOUR-KEY-HERE"                                    
# this is where we will eventually input our API key (*****replace this before testing*****)


def load(path):                              
  # this reads a JSON file, or return {} if it fails
    try:                                     
      # this tries to open and parse the file
        return json.load(open(path))         
      # this opens the file and returns its parsed JSON
    except Exception as e:                         
        print(f"[warn] cannot read {path}: {e}", file=sys.stderr)  
      #   if the file is missing or broken it prints a warning
        return {}                            
      # It then returns an empty dict so we can continue

def collect(discovery, internal):            
  # this turns both inputs into one simple list of findings
    findings = []                            
  # this starts it with an empty list

    for host in discovery.get("hosts", []):  
      # this loops over each discovered host
        for svc in host.get("services", []): 
          # this loops over each service on that host
            findings.append(                 
              # this adds a finding describing the service
                f"{svc.get('tool','AI service')} on {host.get('ip','?')}:{svc.get('port','?')} "
                f"(auth: {svc.get('authenticated','unknown')})")  
          # format of tool, address, and auth state

    for f in internal.get("model_files", []):  
      # this loops over local AI model files
        findings.append(f"Model file: {f.get('path','?')}")  
      # this adds a finding for the file path

    for p in internal.get("processes", []):     
      # this loops over AI-related processes
        findings.append(f"AI process: {p.get('name','?')}")  
      # this adds a finding for the process name

    for k in internal.get("api_keys", []):       
      # this loops over possible API keys on disk
        findings.append(f"Possible API key in: {k.get('path','?')}")  
      # this adds a finding (path only, no secret)

    return findings                          
  # this returns the full list of finding strings


def score(text):                             
  # ask the AI to rate one finding
    prompt = (f"Rate this shadow-AI finding's severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) "
              f"and explain briefly in one sentence: {text}")  # the question we send the AI
    try:                                     
      # try the network call
        r = requests.post(                   
          # send the request to the AI server
            AI_URL,                          
          # the endpoint URL
            headers={"Authorization": f"Bearer {AI_KEY}"},  
          # pass the API key
            json={"model": "gpt-oss",        
                  # which model to use
                  "messages": [{"role": "user", "content": prompt}]},  
          # the prompt
            timeout=30)                      
      # give up after 30 seconds
        return r.json()["choices"][0]["message"]["content"]  
      # return the AI's text reply
    except Exception as e:                   
      # if the AI call fails...
        return f"INFO - (AI unavailable: {e})"  
      # ...fall back to a plain INFO line
