
import json       
# this reads and writes JSON files
import sys        
# this prints warnings to stderr
import requests   
# this sends HTTP requests to the AI server
from NetworkScanner.scanner import ShadowScan
#The network scanner (the Discovery module)

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

    for ip, host in discovery.items():  
      # This loops over each discovered host (The scanner's keys results by IP)
        for ep in host.get("detected_endpoints", []): 
          # This loops over each AI endpoint found on that host
            findings.append(                 
              # this adds a finding describing the service
               f"{ep.get('probable_service','AI service')} on {ip}:{ep.get('port','?')} "
               f"({ep.get('verification','Unverified Service')})")  
                  # service name, address, and whether the scanner verified it
               
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

def main():                                  
  # runs the whole reporting engine
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
  # IP or subnet to scan, e.g. 10.0.0.0/24 (defaults to this machine)
    discovery = ShadowScan().scan_target(target)  
  # this runs the scanner and get its results directly    
    internal = load("internal_results.json")   
  # this loads the internal scan module's output
    findings = collect(discovery, internal)     
  # this merges both into one list of findings

    report = []                              
  # collect the scored lines for the report
    for f in findings:                       
      # loop over each finding
        report.append(f"- {f}\n  {score(f)}")  
      # score it with the AI and format the line

    text = "SHADOW AI SCAN REPORT\n\n" + "\n\n".join(report)  
  # build the full report text
    open("report.txt", "w").write(text)      
  # write the human-readable report to a file
    print(text)                              
  # also print it to the screen


if __name__ == "__main__":                   
  # if this file is run directly...
    main()                                   
# ...start the program
