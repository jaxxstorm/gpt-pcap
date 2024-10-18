import pyshark
from openai import OpenAI
import json
import argparse
import os

# Step 1: Analyze PCAP file using pyshark. A Lua script is optional.
def analyze_pcap_with_lua(pcap_file, lua_script=None, max_packets=None, debug=False, summarize=False):
    """Analyze the PCAP file using pyshark. A Lua script is optional."""
    
    custom_parameters = {}
    # If Lua script is provided, add it to the custom parameters for Tshark
    if lua_script:
        custom_parameters = {'-X': f'lua_script:{lua_script}'}

    # Capture packets with optional Lua script and pyshark
    capture = pyshark.FileCapture(
        input_file=pcap_file,
        tshark_path='tshark',
        custom_parameters=custom_parameters
    )
    
    # Collect summary information
    total_packets = 0
    protocols = {}
    source_ips = set()
    destination_ips = set()
    layer_counts = {}  # Store the count of different layers

    # Loop over packets and analyze
    for packet in capture:
        total_packets += 1

        # If max_packets is specified, check if we've reached the limit
        if max_packets is not None and total_packets > max_packets:
            break

        # Debug mode: Print the full packet information
        if debug:
            print(f"Packet {total_packets}:")
            print(packet)
            print("---------")

        # Extract protocol information and layer summary
        if hasattr(packet, 'ip'):
            proto = packet.transport_layer  # Protocol
            protocols[proto] = protocols.get(proto, 0) + 1
            source_ips.add(packet.ip.src)
            destination_ips.add(packet.ip.dst)

        # Count the layers in each packet
        for layer in packet.layers:
            layer_name = layer.layer_name
            layer_counts[layer_name] = layer_counts.get(layer_name, 0) + 1

    # Prepare a summary of the data
    summary = {
        "total_packets": total_packets,
        "protocol_distribution": protocols,
        "source_ips": list(source_ips),
        "destination_ips": list(destination_ips),
        "layer_counts": layer_counts  # Add layer summary
    }

    if summarize:
        print("\nSummary of Packet Layers and Protocols:")
        print(json.dumps(summary, indent=2))
        print("---------")

    return summary


# jsonify the packet data
def jsonify_packets(packet_summary):
    return json.dumps(packet_summary, indent=2)


# Uploads the PCAP to OpenAI. FIXME: make the prompt configurable
def openai_analyze(data, model, max_tokens):
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "You are a network traffic analysis assistant. Help analyze and extract insights from network packet data.",
            },
            {
                "role": "user",
                "content": f"Here is a network packet capture summary: {data}. Please analyze this data. Summarize the address being connected, how many packets are being sent to those addresses and which protocols are being used. An example of a good response is 'there was 1000 number of packets sent to IP address via SSH'. Identify any failures or items for investigation, or anything that might be concerning to a user.",
            },
        ],
        max_tokens=max_tokens,  # Adjust based on the level of detail you need
    )

    # Accessing the 'content' attribute directly from the message
    message_content = response.choices[0].message.content
    return message_content


# Main analysis function that manages debug, summarize, and OpenAI modes
def run_pcap_analysis(pcap_file, lua_script, model, max_tokens, max_packets=None, debug=False, summarize=False, aisummarize=False):
    # Analyze packets using pyshark with optional Lua script
    packet_summary = analyze_pcap_with_lua(pcap_file, lua_script, max_packets, debug, summarize)
    
    # Handle Debug and Summarize modes
    if debug:
        print("Debug mode: No data sent to OpenAI.")
        return packet_summary
    if summarize:
        print("Summarize mode: No data sent to OpenAI.")
        return packet_summary

    # If --aisummarize flag is set, generate summary and send to OpenAI
    if aisummarize:
        print("AISummarize mode: Sending summary to OpenAI for evaluation.")
        data_for_openai = jsonify_packets(packet_summary)
        insights = openai_analyze(data_for_openai, model, max_tokens)
        return insights

    # Normal mode: Prepare data and query OpenAI
    data_for_openai = jsonify_packets(packet_summary)
    insights = openai_analyze(data_for_openai, model, max_tokens)
    
    return insights


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PCAP files using OpenAI models with optional Lua scripts.")
    
    parser.add_argument("-m", "--model", type=str, default="gpt-4o-mini", help="The OpenAI model to use (e.g., gpt-4, text-davinci-003, etc.)")
    parser.add_argument("-p", "--pcap", type=str, required=True, help="The path to the PCAP file")
    parser.add_argument("-l", "--lua", type=str, help="The path to the Lua script for Tshark (optional)")
    parser.add_argument("--max_packets", type=int, default=None, help="Maximum number of packets to process. Leave blank to process all packets.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode to print packet data and skip OpenAI upload")
    parser.add_argument("--summarize", action="store_true", help="Summarize the layer and protocol details, skip OpenAI upload")
    parser.add_argument("--aisummarize", action="store_true", help="Summarize the packet layers and send summary to OpenAI for evaluation")
    parser.add_argument("--max_tokens", type=int, default=500, help="Tokens to send to OpenAI")

    args = parser.parse_args()

    # Run analysis with the user-specified PCAP file, optional Lua script, and model
    analysis_result = run_pcap_analysis(args.pcap, args.lua, args.model, args.max_tokens, args.max_packets, args.debug, args.summarize, args.aisummarize)

    # Output the result (or packet summary in debug/summarize mode)
    print(analysis_result)
