# NETGPT
This project utilizes ChatGPT to analyze and summarize network traffic. In addition it will point out anything out of the ordinary and any possible security concerns.

## Disclaimer
This project only analyzes ETH, ARP, IPv4, IPv6, TCP, UDP, DNS, HTTP, and TLS. Also by defaults it uses GPT's 4o model so the max amount of packets it can analyze is 280.

### Prerequisties
- Python
- Wireshark
- Pyshark library
- OpenAI library

### How to run
Run main.py in the command line and pass in the .pcapng file you would like to analyze
