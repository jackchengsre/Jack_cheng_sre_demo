/**
 * Jack Cheng's SRE Copilot with AWS Bedrock
 * 
 * Core components for the SRE copilot system
 * 
 * Copyright © 2025 Jack Cheng. All rights reserved.
 * Proprietary and Confidential
 */

import boto3
import json
import logging
import os
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jc-sre-copilot')

class SRECopilotCore:
    """
    Core class for Jack Cheng's SRE Copilot system.
    Handles initialization and common functionality.
    """
    
    def __init__(self, region_name='us-east-1'):
        """
        Initialize the SRE Copilot core system.
        
        Args:
            region_name (str): AWS region name
        """
        self.region_name = region_name
        self.bedrock_runtime = boto3.client('bedrock-runtime', region_name=region_name)
        self.bedrock_agent = boto3.client('bedrock-agent', region_name=region_name)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        self.logs = boto3.client('logs', region_name=region_name)
        logger.info(f"Jack Cheng's SRE Copilot initialized in region {region_name}")
    
    def invoke_bedrock_model(self, prompt, model_id="anthropic.claude-3-sonnet-20240229-v1:0", max_tokens=4096):
        """
        Invoke an AWS Bedrock foundation model.
        
        Args:
            prompt (str): Prompt text to send to the model
            model_id (str): AWS Bedrock foundation model ID
            max_tokens (int): Maximum number of tokens to generate
            
        Returns:
            str: Model response text
        """
        logger.info(f"Invoking AWS Bedrock model: {model_id}")
        
        # Determine which model provider is being used and format accordingly
        if 'anthropic.claude' in model_id:
            # Claude models use a specific format
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
        elif 'amazon.titan' in model_id:
            # Titan models use a different format
            request_body = {
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": max_tokens,
                    "temperature": 0.2,
                    "topP": 0.9
                }
            }
        else:
            # Generic format for other models
            request_body = {
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": 0.2,
                "top_p": 0.9
            }
        
        # Invoke the model
        response = self.bedrock_runtime.invoke_model(
            modelId=model_id,
            body=json.dumps(request_body)
        )
        
        # Parse the response based on the model
        response_body = json.loads(response['body'].read().decode('utf-8'))
        
        if 'anthropic.claude' in model_id:
            return response_body['content'][0]['text']
        elif 'amazon.titan' in model_id:
            return response_body['results'][0]['outputText']
        else:
            return response_body.get('completion', response_body.get('generated_text', ''))

    def create_agent(self, agent_name, model_id, description, instruction):
        """
        Create a new AWS Bedrock agent.
        
        Args:
            agent_name (str): Name of the agent
            model_id (str): AWS Bedrock foundation model ID
            description (str): Description of the agent
            instruction (str): Instructions for the agent
            
        Returns:
            str: Agent ID
        """
        logger.info(f"Creating AWS Bedrock agent: {agent_name}")
        
        response = self.bedrock_agent.create_agent(
            agentName=agent_name,
            foundationModel=model_id,
            description=description,
            instruction=instruction
        )
        
        return response['agentId']
    
    def get_cloudwatch_metrics(self, namespace, metric_name, dimensions, start_time, end_time, period=60):
        """
        Get CloudWatch metrics.
        
        Args:
            namespace (str): Metric namespace
            metric_name (str): Metric name
            dimensions (list): List of dimensions
            start_time (datetime): Start time
            end_time (datetime): End time
            period (int): Period in seconds
            
        Returns:
            dict: CloudWatch metrics data
        """
        logger.info(f"Getting CloudWatch metrics: {namespace}/{metric_name}")
        
        response = self.cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'metric1',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': namespace,
                            'MetricName': metric_name,
                            'Dimensions': dimensions
                        },
                        'Period': period,
                        'Stat': 'Average'
                    }
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        
        return response
    
    def get_cloudwatch_logs(self, log_group_name, start_time, end_time, filter_pattern=''):
        """
        Get CloudWatch logs.
        
        Args:
            log_group_name (str): Log group name
            start_time (datetime): Start time
            end_time (datetime): End time
            filter_pattern (str): Filter pattern
            
        Returns:
            list: CloudWatch log events
        """
        logger.info(f"Getting CloudWatch logs: {log_group_name}")
        
        # Convert datetime to milliseconds since epoch
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
        
        response = self.logs.filter_log_events(
            logGroupName=log_group_name,
            startTime=start_time_ms,
            endTime=end_time_ms,
            filterPattern=filter_pattern
        )
        
        return response['events']
    
    def analyze_logs(self, logs, context=None):
        """
        Analyze logs using AWS Bedrock foundation models.
        
        Args:
            logs (list): List of log events
            context (str): Additional context for analysis
            
        Returns:
            dict: Analysis results
        """
        logger.info("Analyzing logs with AWS Bedrock")
        
        # Prepare logs for analysis
        log_text = "\n".join([event['message'] for event in logs])
        
        # Create prompt for the model
        prompt = f"""
        You are Jack Cheng's SRE Copilot, an expert in analyzing logs for root cause analysis.
        
        Please analyze the following logs and identify:
        1. Any errors or exceptions
        2. Unusual patterns or anomalies
        3. Potential root causes of issues
        4. Recommendations for resolution
        
        {context or ''}
        
        LOGS:
        {log_text}
        
        Provide your analysis in JSON format with the following structure:
        {{
            "errors": [list of errors found],
            "anomalies": [list of anomalies detected],
            "root_causes": [list of potential root causes],
            "recommendations": [list of recommendations]
        }}
        """
        
        # Invoke the model
        response = self.invoke_bedrock_model(prompt)
        
        # Extract JSON from response
        try:
            # Find JSON in the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                analysis = {"error": "No valid JSON found in response"}
        except json.JSONDecodeError:
            analysis = {"error": "Failed to parse JSON from response"}
        
        return analysis
    
    def generate_report(self, analysis_results, incident_description=None):
        """
        Generate a comprehensive incident report based on analysis results.
        
        Args:
            analysis_results (dict): Analysis results
            incident_description (str): Description of the incident
            
        Returns:
            dict: Report data
        """
        logger.info("Generating incident report")
        
        # Create prompt for the model
        prompt = f"""
        You are Jack Cheng's SRE Copilot, an expert in generating incident reports for root cause analysis.
        
        Please generate a comprehensive incident report based on the following analysis results:
        
        {json.dumps(analysis_results, indent=2)}
        
        {f"Incident Description: {incident_description}" if incident_description else ""}
        
        The report should include:
        1. Executive summary
        2. Incident timeline
        3. Root cause analysis
        4. Impact assessment
        5. Resolution actions
        6. Recommendations for prevention
        7. Lessons learned
        
        Provide your report in JSON format with the following structure:
        {{
            "title": "Incident Report",
            "executive_summary": "Brief summary of the incident",
            "timeline": [list of key events with timestamps],
            "root_cause": {{
                "primary_cause": "Primary cause of the incident",
                "contributing_factors": [list of contributing factors]
            }},
            "impact": {{
                "services_affected": [list of affected services],
                "duration": "Duration of the incident",
                "severity": "Severity level"
            }},
            "resolution": [list of actions taken to resolve the incident],
            "recommendations": [list of recommendations for prevention],
            "lessons_learned": [list of lessons learned]
        }}
        """
        
        # Invoke the model
        response = self.invoke_bedrock_model(prompt)
        
        # Extract JSON from response
        try:
            # Find JSON in the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                report = json.loads(json_str)
            else:
                report = {"error": "No valid JSON found in response"}
        except json.JSONDecodeError:
            report = {"error": "Failed to parse JSON from response"}
        
        return report

# Example usage
if __name__ == "__main__":
    # Initialize the SRE Copilot core
    sre_copilot = SRECopilotCore()
    
    # Example: Analyze logs
    logs = [
        {"message": "2025-04-05T10:00:00Z ERROR Failed to create EC2 instance: LimitExceededException"},
        {"message": "2025-04-05T10:01:00Z WARN API throttling detected for EC2 RunInstances API"},
        {"message": "2025-04-05T10:02:00Z ERROR Application scaling failed due to insufficient capacity"}
    ]
    
    analysis = sre_copilot.analyze_logs(logs, "Application deployment failure")
    print(json.dumps(analysis, indent=2))
    
    # Example: Generate report
    report = sre_copilot.generate_report(analysis, "Application deployment failure and increased error rates")
    print(json.dumps(report, indent=2))
