LLM Agent and Evaluation Framework for Autonomous Penetration Testing

A framework for evaluating the performance of Large Language Models (LLMs) in autonomous penetration testing.

Overview
This framework provides a comprehensive evaluation environment for assessing the capabilities of LLMs in autonomous penetration testing. It includes a modular architecture for integrating different LLMs, a simulation environment for testing, and a set of evaluation metrics for assessing performance.

Requirements
- Python 3.8+
- Docker
- NVIDIA GPU (optional)
- transformers library
- torch library
- neptune library
- docker library
- paramiko library
- pyelftools library
- pwntools library

Installation
1. Clone the repository: git clone https://github.com/your-username/llm-agent.git
2. Install required packages: pip install -r requirements.txt
3. Build the Docker image: docker build -t llm-agent .
4. Run the Docker container: docker run -it llm-agent

Usage
1. Configure the framework by modifying the config.json file.
2. Run the evaluation script: python evaluate.py
3. View the results in the Neptune dashboard.

Evaluation Metrics
- Success rate
- Average time to exploit
- Number of failed attempts
- Coverage of vulnerabilities

LLM Integration
The framework provides a modular architecture for integrating different LLMs. Currently, it supports the following LLMs:

- BERT
- RoBERTa
- XLNet

Simulation Environment
The framework includes a simulation environment for testing the LLMs. The environment consists of a set of virtual machines with different vulnerabilities.

Acknowledgments
- Thanks to [RamkotiRK] for creating this project.
