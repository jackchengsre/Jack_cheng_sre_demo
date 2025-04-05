# Jack Cheng's SRE Copilot with AWS Bedrock

## Proprietary and Confidential

This repository contains Jack Cheng's proprietary SRE Copilot solution that leverages AWS Bedrock foundation models to perform root cause analysis with logs, metrics, and dashboards using multi-agent and multi-modal capabilities.

## Overview

Jack Cheng's SRE Copilot is an advanced solution for Site Reliability Engineers that uses AWS Bedrock's foundation models in a multi-agent architecture to analyze different data sources (logs, metrics, dashboards) and collaborate to determine the root cause of incidents. The multi-modal capabilities allow the system to process both textual and visual data for more comprehensive analysis.

## Key Features

- **Multi-Agent Architecture**: Specialized agents collaborate to analyze different data sources
- **Multi-Modal Analysis**: Process text, images, and metrics to understand complex incidents
- **Advanced Log Analysis**: Intelligent parsing and pattern recognition for log data
- **Metrics Correlation**: Correlate metrics across services to identify relationships
- **Dashboard Interpretation**: Extract insights from visual dashboards
- **AWS Service Integration**: Seamless integration with CloudTrail, VPC Flow Logs, Health Dashboard, and Trusted Advisor

## AWS Monitoring Integration

Jack Cheng's SRE Copilot integrates with key AWS monitoring services:

- **AWS CloudTrail**: Analyzes API activity for errors, throttling, and unusual patterns
- **VPC Flow Logs**: Examines network traffic for rejected connections and anomalies
- **AWS Health Dashboard**: Monitors AWS service health events and impacts
- **AWS Trusted Advisor**: Evaluates best practice recommendations and issues

## Root Cause Analysis Process

The event correlation system analyzes data from multiple sources to identify the root cause of incidents:

1. **Data Collection**: Gather logs, metrics, and events from AWS services
2. **Specialized Analysis**: Each agent analyzes its specific data domain
3. **Event Correlation**: Identify relationships between events across services
4. **Root Cause Identification**: Determine the primary cause and contributing factors
5. **Recommendation Generation**: Provide actionable recommendations

## Project Structure

- `/code`: Implementation code for the SRE Copilot
- `/docs`: Documentation including user guide and deployment guide
- `/research`: Research findings and background information
- `/code/monitoring_agents`: Specialized monitoring agents for different data sources
- `/code/demo.py`: Demonstration script to showcase the solution

## Getting Started

See the [Deployment Guide](docs/deployment_guide.md) for instructions on setting up and deploying Jack Cheng's SRE Copilot in your AWS environment.

## License

Copyright © 2025 Jack Cheng. All rights reserved. This is proprietary software.
Unauthorized copying, transfer, or reproduction of the contents of this repository is strictly prohibited.

## Contact

For inquiries about Jack Cheng's SRE Copilot, please contact Jack Cheng directly.
