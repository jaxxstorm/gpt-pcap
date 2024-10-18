# PCAP Analysis Script Using OpenAI

This Python script allows users to analyze network packet captures (PCAP) using `pyshark` and OpenAI models. Optionally, a Lua script can be included for custom dissectors in `Tshark`.

## Features
- **Analyze PCAP files**: Use `pyshark` to extract information such as protocols, source/destination IPs, and packet layers.
- **Optional Lua Script**: Include a Lua script for custom protocol dissections in `Tshark`.
- **OpenAI Integration**: Automatically send a summarized version of the packet data to OpenAI for further analysis.
- **Modes**: Supports debug, summarize, and OpenAI upload modes.

## Prerequisites

- Python 3.6 or above
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Tshark](https://www.wireshark.org/download.html)
- OpenAI Python API (`openai` library)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jaxxstorm/gpt-pcap.git
   cd gpt-pcap
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up OpenAI API Key:**
   You will need an OpenAI API key to interact with OpenAI's models. Set the API key as an environment variable:
   ```bash
   export OPENAI_API_KEY="your-openai-api-key"
   ```

4. **Ensure Tshark is installed:**
   Install `Tshark` if it is not already installed. You can download it from the [Wireshark website](https://www.wireshark.org/download.html).

## Usage

### Command-line Arguments

- `--model` (required): Specify the OpenAI model to use (default: `gpt-4`).
- `--pcap` (required): The path to the PCAP file to be analyzed.
- `--lua`: The path to the Lua script for Tshark (optional).
- `--max_packets`: Maximum number of packets to process (default: process all packets).
- `--debug`: Enable debug mode to print packet details without sending data to OpenAI.
- `--summarize`: Summarize packet layers and protocols, but do not upload data to OpenAI.
- `--aisummarize`: Summarize packet layers and protocols, then upload the summary to OpenAI for evaluation.
- `--max_tokens`: Limit the number of tokens for the OpenAI response (default: 500).

### Example Commands

1. **Analyze a PCAP file without a Lua script and send data to OpenAI:**
   ```bash
   python your_script.py --pcap ~/path/to/capture.pcap --model gpt-4 --max_tokens 500
   ```

2. **Analyze a PCAP file with a Lua script:**
   ```bash
   python your_script.py --pcap ~/path/to/capture.pcap --lua ~/path/to/custom_dissector.lua --model gpt-4 --max_tokens 500
   ```

3. **Run in debug mode (print packet details, no OpenAI interaction):**
   ```bash
   python your_script.py --pcap ~/path/to/capture.pcap --debug
   ```

4. **Run in summarize mode (print packet summary, no OpenAI interaction):**
   ```bash
   python your_script.py --pcap ~/path/to/capture.pcap --summarize
   ```

5. **Summarize the PCAP file and send the summary to OpenAI for analysis:**
   ```bash
   python your_script.py --pcap ~/path/to/capture.pcap --aisummarize --model gpt-4 --max_tokens 500
   ```

### Token Limitations

- Each OpenAI model has a token limit (e.g., `gpt-4` has an 8192-token limit). The `--max_tokens` argument controls how many tokens are returned in the response. Input tokens (the packet summary) also count toward the total.

## License

This project is licensed under the MIT License.