# LLM Testing Tool

This Python tool allows you to test the LLM server by sending user traffic data and observing the anomaly detection responses.

## Features

- 📤 Sends requests to the LLM server using AnLF's prompt templates
- 🎨 Colorful terminal output with highlighted target UEs
- 📊 Displays user traffic data in table format
- 🔄 Continuously processes data from CSV files
- ⚙️ Configurable batch size, temperature, and other LLM parameters

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install requests colorama
```

## Configuration

Edit the configuration section at the top of `test_llm.py`:

```python
# LLM Server Configuration
LLM_SERVER_URL = "http://140.113.208.89:8000"  # Target LLM server endpoint

# Prompt Template Configuration
PROMPT_TEMPLATE_PATH = "/home/vagrant/AnLF/anlf/prompts/anomaly_detection_single_ue.txt"

# User Data Source (CSV file from output directory)
USER_DATA_SOURCE = "/home/vagrant/AnLF/anlf/output/5G-UE/5G-UE.csv"

# LLM Parameters
BATCH_SIZE = 10  # Number of UEs to process per batch
TEMPERATURE = 0.1  # LLM temperature (0.0-2.0, lower = more deterministic)
MAX_TOKENS = 50  # Max response tokens
INCLUDE_GLOBAL_CONTEXT = True  # Include global network statistics in prompt

# Request Configuration
REQUEST_TIMEOUT = 10  # Request timeout in seconds
POLL_INTERVAL = 3  # Seconds between each batch request
```

## Usage

Run the tool:

```bash
python3 test_llm.py
# or
./test_llm.py
```

The tool will:

1. **Display the prompt template** - Shows the full prompt being sent to the LLM
2. **Load CSV data** - Reads user traffic records from the configured CSV file
3. **Process data continuously** - Sends requests for each UE in batches
4. **Display results** - Shows:
   - Request number with separator
   - Target UE (highlighted in green)
   - Traffic data table (target UE in green, others in gray)
   - LLM response (in white)
   - Request timing information

## Output Format

Each request displays:

```
====================================================================================================
 Request #1 
====================================================================================================

 Target UE: imsi-208930000000001 

UE Traffic Data:
────────────────────────────────────────────────────────────────────────────────────────────────────
SUPI                      UL_PPS   UL_Len   Flow     Fan      TCP      SYN      DL_PPS   DL_Len  
────────────────────────────────────────────────────────────────────────────────────────────────────
imsi-208930000000001      0.85     77       0.14     0.03     0.86     0.00     0.70     101      # GREEN (target)
imsi-208930000000002      2.56     54       0.00     0.03     1.00     0.00     2.79     125      # GRAY (others)
imsi-208930000000003      2.52     54       0.01     0.03     0.99     0.00     2.76     106      # GRAY
...
────────────────────────────────────────────────────────────────────────────────────────────────────

Sending request to LLM server...
LLM Response:
Risk Score: 0.1

[Request completed in 1.23s]
```

## Color Scheme

- 🟢 **Green** - Target UE (prominently highlighted)
- ⚪ **White** - LLM responses
- 🔵 **Cyan** - Section headers and separators
- 🟡 **Yellow** - Configuration and data labels
- ⚫ **Gray** - Other UEs in the batch (less prominent)
- 🔴 **Red** - Errors

## CSV Data Format

The tool expects CSV files with the following columns:

- `timestamp`, `supi`, `ue_ip`
- `ul_log_pps`, `global_ul_log_pps`, `dl_log_pps`, `global_dl_log_pps`
- `ul_avg_len`, `global_ul_avg_len`, `dl_avg_len`, `global_dl_avg_len`
- `pps_ratio`, `global_pps_ratio`, `byte_ratio`, `global_byte_ratio`
- `tcp_ratio`, `udp_ratio`, `icmp_ratio`, `syn_ratio`, `rst_ratio`
- `new_flow_rate`, `global_new_flow_rate`, `fan_out`, `global_fan_out`
- `ack_ratio`

Example CSV files are available in `/home/vagrant/AnLF/anlf/output/`:
- `5G-UE/5G-UE.csv` - Normal 5G user traffic
- `Attacker_TCP/Attacker_TCP.csv` - TCP attack traffic
- `Attacker_UDP/Attacker_UDP.csv` - UDP attack traffic

## Stopping the Tool

Press `Ctrl+C` to gracefully stop the tool at any time.

## Troubleshooting

### Connection Errors

If you see connection errors, verify:
- The LLM server is running at the configured URL
- The port is accessible from your machine
- Firewall settings allow connections

### Timeout Errors

If requests timeout:
- Increase `REQUEST_TIMEOUT` in the configuration
- Check if the LLM server is overloaded
- Verify network connectivity

### Invalid CSV Format

If CSV loading fails:
- Ensure the CSV file path is correct
- Verify the CSV has all required columns
- Check that numeric values are valid (no missing data)

## Integration with AnLF

This tool mimics AnLF's anomaly detector behavior:
- Uses the same prompt templates
- Follows the same request format
- Applies the same feature engineering
- Sends identical requests to the LLM server

Use this tool to:
- Test LLM server performance
- Debug prompt templates
- Analyze LLM responses for different traffic patterns
- Validate anomaly detection accuracy
