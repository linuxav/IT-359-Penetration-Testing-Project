
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

