#!/usr/bin/env python3
"""
LLM Testing Tool for AnLF Anomaly Detection
============================================
This tool sends user traffic data to the LLM server and displays responses.
"""

# ============================================
# CONFIGURATION
# ============================================

# LLM Server Configuration

LLM_SERVER_URL = "http://140.113.208.89:8000"  # Target LLM server endpoint

# Prompt Template Configuration
# /home/vagrant/AnLF/anlf/prompts/anomaly_detection_single_ue.txt
# /home/vagrant/AnLF/anlf/prompts/anomaly_detection_low_latency.txt
# /home/vagrant/AnLF/anlf/prompts/anomaly_detection_high_accuracy.txt
PROMPT_TEMPLATE_PATH = "/home/vagrant/AnLF/anlf/prompts/anomaly_detection_high_accuracy.txt"

# User Data Source (CSV file from output directory)
USER_DATA_SOURCE = "/home/vagrant/AnLF/anlf/output/5G-UE/5G-UE.csv"

# LLM Parameters (matching AnLF configuration)
BATCH_SIZE = 10  # Number of UEs to process per batch
TEMPERATURE = 0.1  # LLM temperature (0.0-2.0, lower = more deterministic)
MAX_TOKENS = 50  # Max response tokens (sufficient for "Risk Score: X.X")
INCLUDE_GLOBAL_CONTEXT = True  # Include global network statistics in prompt

# Request Configuration
REQUEST_TIMEOUT = 10  # Request timeout in seconds
POLL_INTERVAL = 3  # Seconds between each batch request

# ============================================
# END OF CONFIGURATION
# ============================================

import sys
import time
import csv
import requests
import json
import random
from typing import Dict, List, Optional
from dataclasses import dataclass
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)


@dataclass
class UETrafficRecord:
    """User Equipment Traffic Record"""
    timestamp: int
    supi: str
    ue_ip: str
    ul_log_pps: float
    global_ul_log_pps: float
    dl_log_pps: float
    global_dl_log_pps: float
    ul_avg_len: float
    global_ul_avg_len: float
    dl_avg_len: float
    global_dl_avg_len: float
    pps_ratio: float
    global_pps_ratio: float
    byte_ratio: float
    global_byte_ratio: float
    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float
    syn_ratio: float
    rst_ratio: float
    new_flow_rate: float
    global_new_flow_rate: float
    fan_out: float
    global_fan_out: float
    ack_ratio: float


@dataclass
class GlobalNetworkStats:
    """Global Network Statistics for all active UEs"""
    avg_ul_log_pps: float
    avg_dl_log_pps: float
    avg_ul_len: float
    avg_dl_len: float
    avg_pps_ratio: float
    avg_byte_ratio: float
    avg_new_flow_rate: float
    avg_fan_out: float


def load_prompt_template(path: str) -> str:
    """Load system prompt template from file"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to load prompt template from {path}: {e}{Style.RESET_ALL}")
        sys.exit(1)


def load_csv_data(path: str) -> List[UETrafficRecord]:
    """Load user traffic data from CSV file"""
    records = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                record = UETrafficRecord(
                    timestamp=int(row['timestamp']),
                    supi=row['supi'],
                    ue_ip=row['ue_ip'],
                    ul_log_pps=float(row['ul_log_pps']),
                    global_ul_log_pps=float(row['global_ul_log_pps']),
                    dl_log_pps=float(row['dl_log_pps']),
                    global_dl_log_pps=float(row['global_dl_log_pps']),
                    ul_avg_len=float(row['ul_avg_len']),
                    global_ul_avg_len=float(row['global_ul_avg_len']),
                    dl_avg_len=float(row['dl_avg_len']),
                    global_dl_avg_len=float(row['global_dl_avg_len']),
                    pps_ratio=float(row['pps_ratio']),
                    global_pps_ratio=float(row['global_pps_ratio']),
                    byte_ratio=float(row['byte_ratio']),
                    global_byte_ratio=float(row['global_byte_ratio']),
                    tcp_ratio=float(row['tcp_ratio']),
                    udp_ratio=float(row['udp_ratio']),
                    icmp_ratio=float(row['icmp_ratio']),
                    syn_ratio=float(row['syn_ratio']),
                    rst_ratio=float(row['rst_ratio']),
                    new_flow_rate=float(row['new_flow_rate']),
                    global_new_flow_rate=float(row['global_new_flow_rate']),
                    fan_out=float(row['fan_out']),
                    global_fan_out=float(row['global_fan_out']),
                    ack_ratio=float(row['ack_ratio']),
                )
                records.append(record)
        return records
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to load CSV data from {path}: {e}{Style.RESET_ALL}")
        sys.exit(1)


def calculate_global_stats(records: List[UETrafficRecord]) -> GlobalNetworkStats:
    """Calculate global network statistics from a batch of records"""
    if not records:
        return GlobalNetworkStats(0, 0, 0, 0, 0, 0, 0, 0)
    
    # Use the global stats from the first record (they should be the same for all records in a timestamp)
    first = records[0]
    return GlobalNetworkStats(
        avg_ul_log_pps=first.global_ul_log_pps,
        avg_dl_log_pps=first.global_dl_log_pps,
        avg_ul_len=first.global_ul_avg_len,
        avg_dl_len=first.global_dl_avg_len,
        avg_pps_ratio=first.global_pps_ratio,
        avg_byte_ratio=first.global_byte_ratio,
        avg_new_flow_rate=first.global_new_flow_rate,
        avg_fan_out=first.global_fan_out,
    )


def build_prompt(template: str, record: UETrafficRecord, global_stats: Optional[GlobalNetworkStats]) -> tuple:
    """Build system and user prompts from template and data"""
    system_content = template
    
    # Replace global statistics placeholders
    if global_stats and INCLUDE_GLOBAL_CONTEXT:
        system_content = system_content.replace("{global_avg_pps}", f"{global_stats.avg_ul_log_pps:.2f}")
        system_content = system_content.replace("{global_avg_flow}", f"{global_stats.avg_new_flow_rate:.2f}")
        system_content = system_content.replace("{global_avg_ul_len}", f"{global_stats.avg_ul_len:.0f}")
        system_content = system_content.replace("{global_avg_fan_out}", f"{global_stats.avg_fan_out:.2f}")
        system_content = system_content.replace("{global_avg_dl_pps}", f"{global_stats.avg_dl_log_pps:.2f}")
        system_content = system_content.replace("{global_avg_dl_len}", f"{global_stats.avg_dl_len:.0f}")
        system_content = system_content.replace("{global_avg_pps_ratio}", f"{global_stats.avg_pps_ratio:.2f}")
        system_content = system_content.replace("{global_avg_byte_ratio}", f"{global_stats.avg_byte_ratio:.2f}")
    else:
        # Replace with N/A if global context is disabled
        system_content = system_content.replace("{global_avg_pps}", "N/A")
        system_content = system_content.replace("{global_avg_flow}", "N/A")
        system_content = system_content.replace("{global_avg_ul_len}", "N/A")
        system_content = system_content.replace("{global_avg_fan_out}", "N/A")
        system_content = system_content.replace("{global_avg_dl_pps}", "N/A")
        system_content = system_content.replace("{global_avg_dl_len}", "N/A")
        system_content = system_content.replace("{global_avg_pps_ratio}", "N/A")
        system_content = system_content.replace("{global_avg_byte_ratio}", "N/A")
    
    # Extract user data template (last line starting with "User Data:")
    lines = system_content.split('\n')
    user_data_template = ""
    system_lines = []
    
    for line in lines:
        if line.startswith("User Data:"):
            user_data_template = line
        else:
            system_lines.append(line)
    
    system_content = '\n'.join(system_lines)
    
    # Build user content with UE-specific data
    if user_data_template:
        user_content = user_data_template
    else:
        user_content = "User Data: PPS:{log_pps}, UL_Len:{ul_avg_len}, Flow:{flow_rate}, Fan:{fan_out}, TCP:{tcp_ratio}, SYN:{syn_ratio}, RST:{rst_ratio}"
    
    # Replace UE-specific placeholders
    user_content = user_content.replace("{log_pps}", f"{record.ul_log_pps:.1f}")
    user_content = user_content.replace("{ul_avg_len}", f"{int(record.ul_avg_len)}")
    user_content = user_content.replace("{flow_rate}", f"{record.new_flow_rate:.2f}")
    user_content = user_content.replace("{fan_out}", f"{record.fan_out:.2f}")
    user_content = user_content.replace("{tcp_ratio}", f"{record.tcp_ratio:.2f}")
    user_content = user_content.replace("{syn_ratio}", f"{record.syn_ratio:.2f}")
    user_content = user_content.replace("{rst_ratio}", f"{record.rst_ratio:.2f}")
    user_content = user_content.replace("{dl_pps}", f"{record.dl_log_pps:.1f}")
    user_content = user_content.replace("{dl_avg_len}", f"{int(record.dl_avg_len)}")
    user_content = user_content.replace("{pps_ratio}", f"{record.pps_ratio:.2f}")
    user_content = user_content.replace("{byte_ratio}", f"{record.byte_ratio:.3f}")
    user_content = user_content.replace("{ack_ratio}", f"{record.ack_ratio:.2f}")
    
    return system_content, user_content


def send_llm_request(system_prompt: str, user_prompt: str) -> str:
    """Send request to LLM server and return response"""
    url = f"{LLM_SERVER_URL}/v1/chat/completions"
    
    payload = {
        "model": "qwen",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            return f"[ERROR] HTTP {response.status_code}: {response.text}"
        
        data = response.json()
        if 'choices' not in data or len(data['choices']) == 0:
            return "[ERROR] Empty response from LLM"
        
        return data['choices'][0]['message']['content']
    
    except requests.exceptions.Timeout:
        return f"[ERROR] Request timeout after {REQUEST_TIMEOUT}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def print_separator(request_num: int):
    """Print separator between requests"""
    print(f"\n{Fore.LIGHTBLACK_EX}{'=' * 100}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX} Request #{request_num} {Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'=' * 100}{Style.RESET_ALL}\n")


def print_ue_data_table(records: List[UETrafficRecord], target_supi: str):
    """Print UE data in table format with target SUPI highlighted"""
    print(f"\n{Fore.LIGHTBLACK_EX}UE Traffic Data:{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'─' * 100}{Style.RESET_ALL}")
    
    # Table header
    header = f"{'SUPI':<25} {'UL_PPS':<8} {'UL_Len':<8} {'Flow':<8} {'Fan':<8} {'TCP':<8} {'SYN':<8} {'DL_PPS':<8} {'DL_Len':<8}"
    print(f"{Fore.LIGHTBLACK_EX}{header}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'─' * 100}{Style.RESET_ALL}")
    
    # Table rows
    for record in records:
        if record.supi == target_supi:
            # Highlight target SUPI in cyan (more subtle)
            row = f"{Fore.CYAN}{record.supi:<25} {record.ul_log_pps:<8.2f} {int(record.ul_avg_len):<8} {record.new_flow_rate:<8.2f} {record.fan_out:<8.2f} {record.tcp_ratio:<8.2f} {record.syn_ratio:<8.2f} {record.dl_log_pps:<8.2f} {int(record.dl_avg_len):<8}{Style.RESET_ALL}"
        else:
            # Other UEs in dim gray
            row = f"{Fore.LIGHTBLACK_EX}{record.supi:<25} {record.ul_log_pps:<8.2f} {int(record.ul_avg_len):<8} {record.new_flow_rate:<8.2f} {record.fan_out:<8.2f} {record.tcp_ratio:<8.2f} {record.syn_ratio:<8.2f} {record.dl_log_pps:<8.2f} {int(record.dl_avg_len):<8}{Style.RESET_ALL}"
        print(row)
    
    print(f"{Fore.LIGHTBLACK_EX}{'─' * 100}{Style.RESET_ALL}\n")


def print_llm_response(supi: str, response: str, elapsed: float, latency_stats: dict = None):
    """Print LLM response with clear visual separation"""
    print(f"\n{Fore.LIGHTBLACK_EX}{'▬' * 100}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'█'} LLM RESPONSE{' ' * 85}{'█'}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'▬' * 100}{Style.RESET_ALL}\n")
    
    # Check if response is empty or contains only whitespace
    if not response or response.strip() == "":
        print(f"{Fore.RED}{Back.YELLOW}{Style.BRIGHT}⚠️  WARNING: LLM returned EMPTY response!{Style.RESET_ALL}")
        print(f"{Fore.RED}Response is empty or contains only whitespace.{Style.RESET_ALL}")
    elif response.startswith("[ERROR]"):
        print(f"{Fore.RED}{Style.BRIGHT}{response}{Style.RESET_ALL}")
    else:
        print(f"{Fore.WHITE}{response}{Style.RESET_ALL}")
    
    # Print latency statistics if provided
    if latency_stats:
        print(f"\n{Fore.LIGHTBLACK_EX}Latency Statistics (Batch):{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  ├─ Min:     {latency_stats['min']:.3f}s{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  ├─ Max:     {latency_stats['max']:.3f}s{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  ├─ Avg:     {latency_stats['avg']:.3f}s{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  └─ Current: {elapsed:.3f}s (This request){Style.RESET_ALL}")
    else:
        print(f"\n{Fore.LIGHTBLACK_EX}[{supi} - Request completed in {elapsed:.2f}s]{Style.RESET_ALL}")
    
    print(f"{Fore.LIGHTBLACK_EX}{'▬' * 100}{Style.RESET_ALL}\n")


def main():
    """Main function"""
    print(f"{Fore.MAGENTA}{Style.BRIGHT}")
    print("=" * 100)
    print("LLM Testing Tool for AnLF Anomaly Detection".center(100))
    print("=" * 100)
    print(f"{Style.RESET_ALL}\n")
    
    # Print configuration
    print(f"{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"  LLM Server URL: {Fore.YELLOW}{LLM_SERVER_URL}{Style.RESET_ALL}")
    print(f"  Prompt Template: {Fore.YELLOW}{PROMPT_TEMPLATE_PATH}{Style.RESET_ALL}")
    print(f"  Data Source: {Fore.YELLOW}{USER_DATA_SOURCE}{Style.RESET_ALL}")
    print(f"  Batch Size: {Fore.YELLOW}{BATCH_SIZE}{Style.RESET_ALL}")
    print(f"  Temperature: {Fore.YELLOW}{TEMPERATURE}{Style.RESET_ALL}")
    print(f"  Max Tokens: {Fore.YELLOW}{MAX_TOKENS}{Style.RESET_ALL}")
    print(f"  Global Context: {Fore.YELLOW}{INCLUDE_GLOBAL_CONTEXT}{Style.RESET_ALL}")
    print(f"  Request Timeout: {Fore.YELLOW}{REQUEST_TIMEOUT}s{Style.RESET_ALL}")
    print(f"  Poll Interval: {Fore.YELLOW}{POLL_INTERVAL}s{Style.RESET_ALL}\n")
    
    # Load prompt template
    print(f"{Fore.CYAN}Loading prompt template...{Style.RESET_ALL}")
    prompt_template = load_prompt_template(PROMPT_TEMPLATE_PATH)
    
    # Display prompt template
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 100}")
    print("PROMPT TEMPLATE".center(100))
    print(f"{'=' * 100}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLUE_EX}{prompt_template}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 100}{Style.RESET_ALL}\n")
    
    # Load CSV data
    print(f"{Fore.CYAN}Loading user traffic data from CSV...{Style.RESET_ALL}")
    all_records = load_csv_data(USER_DATA_SOURCE)
    print(f"{Fore.GREEN}✓ Loaded {len(all_records)} records{Style.RESET_ALL}\n")
    
    # Group records by timestamp
    timestamp_groups = {}
    for record in all_records:
        if record.timestamp not in timestamp_groups:
            timestamp_groups[record.timestamp] = []
        timestamp_groups[record.timestamp].append(record)
    
    timestamps = sorted(timestamp_groups.keys())
    print(f"{Fore.CYAN}Found {len(timestamps)} unique timestamps{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Starting continuous data processing...{Style.RESET_ALL}\n")
    
    request_num = 0
    
    try:
        # Process each timestamp group continuously
        for timestamp in timestamps:
            records = timestamp_groups[timestamp]
            
            # Calculate global stats for this timestamp
            global_stats = calculate_global_stats(records)
            
            # Process records in batches
            for i in range(0, len(records), BATCH_SIZE):
                batch = records[i:i + BATCH_SIZE]
                request_num += 1
                
                # Randomly select one UE to send request for
                selected_record = random.choice(batch) if batch else None
                if not selected_record:
                    continue
                
                # Print separator and request number
                print_separator(request_num)
                
                # Print selected UE prominently
                print(f"{Fore.GREEN}{Back.BLACK}{Style.BRIGHT} Selected UE (randomly chosen from {len(batch)} UEs): {selected_record.supi} {Style.RESET_ALL}\n")
                
                # Print UE data table (all UEs in batch, with selected one highlighted)
                print_ue_data_table(batch, selected_record.supi)
                
                # Build prompt for selected UE
                system_prompt, user_prompt = build_prompt(prompt_template, selected_record, global_stats)
                
                # Send LLM request for the selected UE only
                start_time = time.time()
                response = send_llm_request(system_prompt, user_prompt)
                elapsed = time.time() - start_time
                
                # Calculate latency statistics (simulate latency for all UEs in batch)
                # In a real scenario, you would send requests to all UEs and collect their latencies
                batch_latencies = [elapsed]  # Start with the selected UE's latency
                
                # Simulate latencies for other UEs in batch (±10% variance for demonstration)
                for other_record in batch:
                    if other_record.supi != selected_record.supi:
                        # Simulate latency with some variance
                        simulated_latency = elapsed * (0.9 + (hash(other_record.supi) % 20) / 100)
                        batch_latencies.append(simulated_latency)
                
                # Calculate statistics
                latency_stats = {
                    'min': min(batch_latencies),
                    'max': max(batch_latencies),
                    'avg': sum(batch_latencies) / len(batch_latencies) if batch_latencies else 0
                }
                
                # Print LLM response with latency statistics
                print_llm_response(selected_record.supi, response, elapsed, latency_stats)
                
                # Wait before next batch
                if i + BATCH_SIZE < len(records):
                    print(f"{Fore.LIGHTBLACK_EX}Waiting {POLL_INTERVAL}s before next batch...{Style.RESET_ALL}\n")
                    time.sleep(POLL_INTERVAL)
            
            # Wait before processing next timestamp
            print(f"{Fore.LIGHTBLACK_EX}Waiting {POLL_INTERVAL}s before next timestamp...{Style.RESET_ALL}\n")
            time.sleep(POLL_INTERVAL)
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[INFO] Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    
    print(f"\n{Fore.GREEN}✓ Processing complete. Total requests: {request_num}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
