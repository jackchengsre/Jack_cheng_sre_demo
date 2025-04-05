"""
AWS Bedrock Monitoring Agents Module

This module implements specialized AWS Bedrock agents for monitoring different AWS services:
- CloudTrail Agent: Analyzes API activity and detects errors, throttling, and access issues
- VPC Flow Logs Agent: Analyzes network traffic and identifies blocked connections
- Health Dashboard Agent: Monitors service health events and their impact
- Trusted Advisor Agent: Evaluates best practice recommendations and identifies issues

These agents use AWS Bedrock foundation models to provide intelligent analysis and insights.
"""

import json
import logging
import datetime
import boto3
from typing import Dict, List, Any, Optional, Union

from aws_monitoring_integration import (
    CloudTrailIntegration,
    VPCFlowLogsIntegration,
    HealthDashboardIntegration,
    TrustedAdvisorIntegration
)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BedrockAgentBase:
    """Base class for AWS Bedrock monitoring agents."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """
        Initialize the AWS Bedrock agent.
        
        Args:
            region_name: AWS region name
            model_id: AWS Bedrock foundation model ID to use
        """
        self.region_name = region_name
        self.model_id = model_id
        self.bedrock_runtime = boto3.client('bedrock-runtime', region_name=region_name)
        logger.info(f"Initialized AWS Bedrock agent with model {model_id} in region {region_name}")
    
    def _invoke_model(self, prompt: str, max_tokens: int = 2048) -> str:
        """
        Invoke the AWS Bedrock foundation model.
        
        Args:
            prompt: Prompt text to send to the model
            max_tokens: Maximum number of tokens to generate
            
        Returns:
            Model response text
        """
        try:
            # Determine which model provider is being used and format accordingly
            if 'anthropic.claude' in self.model_id:
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
            elif 'amazon.titan' in self.model_id:
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
                modelId=self.model_id,
                body=json.dumps(request_body)
            )
            
            # Parse the response based on the model
            response_body = json.loads(response['body'].read().decode('utf-8'))
            
            if 'anthropic.claude' in self.model_id:
                return response_body['content'][0]['text']
            elif 'amazon.titan' in self.model_id:
                return response_body['results'][0]['outputText']
            else:
                return response_body.get('completion', response_body.get('generated_text', ''))
            
        except Exception as e:
            logger.error(f"Error invoking Bedrock model: {e}")
            return f"Error: {str(e)}"
    
    def _format_timestamp(self, timestamp: datetime.datetime) -> str:
        """Format timestamp to ISO 8601 string."""
        if isinstance(timestamp, datetime.datetime):
            return timestamp.isoformat()
        return timestamp


class CloudTrailAgent(BedrockAgentBase):
    """Agent for analyzing AWS CloudTrail logs and detecting API issues."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """Initialize CloudTrail agent."""
        super().__init__(region_name, model_id)
        self.cloudtrail = CloudTrailIntegration(region_name)
        logger.info("CloudTrail agent initialized")
    
    def analyze_api_errors(self, 
                          start_time: Optional[Union[datetime.datetime, str]] = None,
                          end_time: Optional[Union[datetime.datetime, str]] = None,
                          max_results: int = 100) -> Dict[str, Any]:
        """
        Analyze API errors, throttling events, and access denied events in CloudTrail.
        
        Args:
            start_time: Start time for the analysis (default: 24 hours ago)
            end_time: End time for the analysis (default: now)
            max_results: Maximum number of events to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Get API errors from CloudTrail
        error_data = self.cloudtrail.find_api_errors(
            start_time=start_time,
            end_time=end_time,
            max_results=max_results
        )
        
        if error_data["status"] != "success":
            return error_data
        
        # If no errors found, return early
        if error_data["error_event_count"] == 0:
            return {
                "status": "success",
                "service": "CloudTrail Agent",
                "analysis": "No API errors found in the specified time range.",
                "raw_data": error_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS SRE expert analyzing CloudTrail logs for API errors, throttling events, and access denied events.
        
        Here is the summary of the CloudTrail analysis:
        - Total events analyzed: {error_data["total_events_analyzed"]}
        - Error events: {error_data["error_event_count"]}
        - Throttle events: {error_data["throttle_event_count"]}
        - Access denied events: {error_data["access_denied_event_count"]}
        
        Here are the detailed error events:
        {json.dumps(error_data["error_events"][:10], indent=2)}
        
        Here are the throttle events:
        {json.dumps(error_data["throttle_events"][:10], indent=2)}
        
        Here are the access denied events:
        {json.dumps(error_data["access_denied_events"][:10], indent=2)}
        
        Please analyze these events and provide:
        1. A summary of the key issues detected
        2. Patterns or trends in the errors
        3. Potential root causes for these issues
        4. Recommendations for resolving these issues
        5. Severity assessment (Critical, High, Medium, Low)
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the issues",
            "patterns": ["Pattern 1", "Pattern 2", ...],
            "potential_causes": ["Cause 1", "Cause 2", ...],
            "recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "severity": "High/Medium/Low",
            "affected_services": ["Service 1", "Service 2", ...],
            "affected_apis": ["API 1", "API 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "CloudTrail Agent",
            "analysis": analysis,
            "raw_data": error_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def detect_unusual_api_activity(self,
                                   start_time: Optional[Union[datetime.datetime, str]] = None,
                                   end_time: Optional[Union[datetime.datetime, str]] = None,
                                   max_results: int = 100) -> Dict[str, Any]:
        """
        Detect unusual API activity patterns in CloudTrail logs.
        
        Args:
            start_time: Start time for the analysis (default: 24 hours ago)
            end_time: End time for the analysis (default: now)
            max_results: Maximum number of events to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Get management events from CloudTrail
        events_data = self.cloudtrail.get_management_events(
            start_time=start_time,
            end_time=end_time,
            max_results=max_results
        )
        
        if events_data["status"] != "success":
            return events_data
        
        # If no events found, return early
        if events_data["event_count"] == 0:
            return {
                "status": "success",
                "service": "CloudTrail Agent",
                "analysis": "No API activity found in the specified time range.",
                "raw_data": events_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS SRE expert analyzing CloudTrail logs for unusual API activity patterns.
        
        Here is the summary of the CloudTrail events:
        - Total events: {events_data["event_count"]}
        
        Here are the detailed events:
        {json.dumps(events_data["events"][:20], indent=2)}
        
        Please analyze these events and provide:
        1. A summary of the API activity
        2. Any unusual patterns or anomalies detected
        3. Potential security concerns
        4. Recommendations for further investigation
        5. Risk assessment (High, Medium, Low)
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the API activity",
            "unusual_patterns": ["Pattern 1", "Pattern 2", ...],
            "security_concerns": ["Concern 1", "Concern 2", ...],
            "investigation_recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "risk_level": "High/Medium/Low",
            "notable_events": ["Event 1", "Event 2", ...],
            "affected_services": ["Service 1", "Service 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "CloudTrail Agent",
            "analysis": analysis,
            "raw_data": events_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }


class VPCFlowLogsAgent(BedrockAgentBase):
    """Agent for analyzing VPC Flow Logs and detecting network issues."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """Initialize VPC Flow Logs agent."""
        super().__init__(region_name, model_id)
        self.vpc_flow_logs = VPCFlowLogsIntegration(region_name)
        logger.info("VPC Flow Logs agent initialized")
    
    def analyze_rejected_traffic(self,
                               log_group_name: str,
                               start_time: Optional[Union[datetime.datetime, str]] = None,
                               end_time: Optional[Union[datetime.datetime, str]] = None,
                               limit: int = 1000) -> Dict[str, Any]:
        """
        Analyze rejected traffic patterns in VPC Flow Logs.
        
        Args:
            log_group_name: CloudWatch Logs group name for the flow logs
            start_time: Start time for the analysis (default: 1 hour ago)
            end_time: End time for the analysis (default: now)
            limit: Maximum number of log events to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Get rejected traffic from VPC Flow Logs
        rejected_data = self.vpc_flow_logs.find_rejected_traffic(
            log_group_name=log_group_name,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )
        
        if rejected_data["status"] != "success":
            return rejected_data
        
        # If no rejected traffic found, return early
        if rejected_data["rejected_event_count"] == 0:
            return {
                "status": "success",
                "service": "VPC Flow Logs Agent",
                "analysis": "No rejected traffic found in the specified time range.",
                "raw_data": rejected_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS network security expert analyzing VPC Flow Logs for rejected traffic patterns.
        
        Here is the summary of the VPC Flow Logs analysis:
        - Total events analyzed: {rejected_data["total_events_analyzed"]}
        - Rejected events: {rejected_data["rejected_event_count"]}
        - Rejection patterns: {rejected_data["rejection_pattern_count"]}
        
        Here are the detailed rejection patterns:
        {json.dumps(rejected_data["rejection_patterns"][:10], indent=2)}
        
        Please analyze these patterns and provide:
        1. A summary of the rejected traffic patterns
        2. Potential security implications
        3. Possible causes for the rejected traffic
        4. Recommendations for addressing these issues
        5. Security risk assessment (Critical, High, Medium, Low)
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the rejected traffic",
            "security_implications": ["Implication 1", "Implication 2", ...],
            "possible_causes": ["Cause 1", "Cause 2", ...],
            "recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "risk_level": "High/Medium/Low",
            "notable_patterns": ["Pattern 1", "Pattern 2", ...],
            "affected_resources": ["Resource 1", "Resource 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "VPC Flow Logs Agent",
            "analysis": analysis,
            "raw_data": rejected_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def detect_network_anomalies(self,
                               log_group_name: str,
                               start_time: Optional[Union[datetime.datetime, str]] = None,
                               end_time: Optional[Union[datetime.datetime, str]] = None,
                               limit: int = 1000) -> Dict[str, Any]:
        """
        Detect network traffic anomalies in VPC Flow Logs.
        
        Args:
            log_group_name: CloudWatch Logs group name for the flow logs
            start_time: Start time for the analysis (default: 1 hour ago)
            end_time: End time for the analysis (default: now)
            limit: Maximum number of log events to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Get flow log events
        flow_data = self.vpc_flow_logs.get_flow_log_events(
            log_group_name=log_group_name,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )
        
        if flow_data["status"] != "success":
            return flow_data
        
        # If no events found, return early
        if flow_data["event_count"] == 0:
            return {
                "status": "success",
                "service": "VPC Flow Logs Agent",
                "analysis": "No network traffic found in the specified time range.",
                "raw_data": flow_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS network expert analyzing VPC Flow Logs for traffic anomalies and patterns.
        
        Here is the summary of the VPC Flow Logs:
        - Total events: {flow_data["event_count"]}
        - Log group: {flow_data["log_group"]}
        
        Here are the detailed flow log events:
        {json.dumps(flow_data["events"][:20], indent=2)}
        
        Please analyze these events and provide:
        1. A summary of the network traffic patterns
        2. Any anomalies or unusual traffic patterns
        3. Potential security or performance concerns
        4. Recommendations for further investigation or optimization
        5. Risk assessment (High, Medium, Low)
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the network traffic",
            "traffic_patterns": ["Pattern 1", "Pattern 2", ...],
            "anomalies": ["Anomaly 1", "Anomaly 2", ...],
            "concerns": ["Concern 1", "Concern 2", ...],
            "recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "risk_level": "High/Medium/Low",
            "notable_connections": ["Connection 1", "Connection 2", ...],
            "top_talkers": ["IP 1", "IP 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "VPC Flow Logs Agent",
            "analysis": analysis,
            "raw_data": flow_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }


class HealthDashboardAgent(BedrockAgentBase):
    """Agent for analyzing AWS Health Dashboard events and service health."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """Initialize Health Dashboard agent."""
        super().__init__(region_name, model_id)
        self.health_dashboard = HealthDashboardIntegration(region_name)
        logger.info("Health Dashboard agent initialized")
    
    def analyze_service_health(self,
                              start_time: Optional[Union[datetime.datetime, str]] = None,
                              end_time: Optional[Union[datetime.datetime, str]] = None) -> Dict[str, Any]:
        """
        Analyze AWS service health events and their impact.
        
        Args:
            start_time: Start time for the analysis (default: 7 days ago)
            end_time: End time for the analysis (default: now)
            
        Returns:
            Dictionary containing analysis results
        """
        # Get service health summary
        health_data = self.health_dashboard.get_service_health_summary()
        
        if health_data["status"] != "success":
            return health_data
        
        # If no active events found, return early
        if health_data["active_event_count"] == 0:
            return {
                "status": "success",
                "service": "Health Dashboard Agent",
                "analysis": "No active AWS service health events found.",
                "raw_data": health_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS SRE expert analyzing AWS Health Dashboard events and service health.
        
        Here is the summary of the AWS Health Dashboard:
        - Total events: {health_data["total_event_count"]}
        - Active events: {health_data["active_event_count"]}
        
        Here are the service summaries:
        {json.dumps(health_data["service_summary"], indent=2)}
        
        Here are the region summaries:
        {json.dumps(health_data["region_summary"], indent=2)}
        
        Here are the category summaries:
        {json.dumps(health_data["category_summary"], indent=2)}
        
        Here are the active events:
        {json.dumps(health_data["active_events"][:10], indent=2)}
        
        Please analyze these events and provide:
        1. A summary of the current AWS service health status
        2. Assessment of the impact on different services and regions
        3. Recommendations for mitigating the impact
        4. Overall severity assessment (Critical, High, Medium, Low)
        5. Expected resolution timeline based on similar past events
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the service health status",
            "impacted_services": ["Service 1", "Service 2", ...],
            "impacted_regions": ["Region 1", "Region 2", ...],
            "impact_assessment": "Description of the impact",
            "mitigation_recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "severity": "High/Medium/Low",
            "estimated_resolution": "Estimated resolution timeline",
            "key_events": ["Event 1", "Event 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Health Dashboard Agent",
            "analysis": analysis,
            "raw_data": health_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def assess_service_impact(self,
                             event_arns: List[str]) -> Dict[str, Any]:
        """
        Assess the impact of specific AWS Health events.
        
        Args:
            event_arns: List of AWS Health event ARNs to assess
            
        Returns:
            Dictionary containing impact assessment
        """
        # Get health events
        events_data = self.health_dashboard.get_health_events()
        
        if events_data["status"] != "success":
            return events_data
        
        # Filter for the specified events
        target_events = []
        for event in events_data["events"]:
            if event["arn"] in event_arns:
                target_events.append(event)
        
        # If no matching events found, return early
        if not target_events:
            return {
                "status": "success",
                "service": "Health Dashboard Agent",
                "analysis": "No matching AWS Health events found for the specified ARNs.",
                "raw_data": {"event_arns": event_arns},
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS SRE expert assessing the impact of specific AWS Health events.
        
        Here are the events to assess:
        {json.dumps(target_events, indent=2)}
        
        Please analyze these events and provide:
        1. A summary of each event and its impact
        2. Assessment of the overall impact on affected services
        3. Recommendations for mitigating the impact
        4. Severity assessment for each event (Critical, High, Medium, Low)
        5. Expected resolution timeline based on the event details
        
        Format your response as JSON with the following structure:
        {{
            "event_assessments": [
                {{
                    "event_arn": "ARN of the event",
                    "summary": "Brief summary of the event",
                    "impact": "Description of the impact",
                    "severity": "High/Medium/Low",
                    "estimated_resolution": "Estimated resolution timeline",
                    "mitigation_recommendations": ["Recommendation 1", "Recommendation 2", ...]
                }},
                ...
            ],
            "overall_assessment": "Overall assessment of all events",
            "overall_severity": "High/Medium/Low",
            "overall_recommendations": ["Recommendation 1", "Recommendation 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Health Dashboard Agent",
            "analysis": analysis,
            "raw_data": {"events": target_events},
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }


class TrustedAdvisorAgent(BedrockAgentBase):
    """Agent for analyzing AWS Trusted Advisor recommendations and issues."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """Initialize Trusted Advisor agent."""
        super().__init__(region_name, model_id)
        self.trusted_advisor = TrustedAdvisorIntegration(region_name)
        logger.info("Trusted Advisor agent initialized")
    
    def analyze_trusted_advisor_issues(self) -> Dict[str, Any]:
        """
        Analyze AWS Trusted Advisor issues and provide recommendations.
        
        Returns:
            Dictionary containing analysis results
        """
        # Get Trusted Advisor issues
        issues_data = self.trusted_advisor.get_trusted_advisor_issues()
        
        if issues_data["status"] != "success":
            return issues_data
        
        # If no issues found, return early
        if issues_data["issue_count"] == 0:
            return {
                "status": "success",
                "service": "Trusted Advisor Agent",
                "analysis": "No AWS Trusted Advisor issues found.",
                "raw_data": issues_data,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS best practices expert analyzing AWS Trusted Advisor issues.
        
        Here is the summary of the AWS Trusted Advisor issues:
        - Total issues: {issues_data["issue_count"]}
        
        Here are the detailed issues:
        {json.dumps(issues_data["issues"], indent=2)}
        
        Please analyze these issues and provide:
        1. A summary of the key issues and their impact
        2. Prioritization of issues based on severity and potential impact
        3. Detailed recommendations for addressing each category of issues
        4. Overall assessment of the AWS environment health
        5. Potential cost, performance, and security implications
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the Trusted Advisor issues",
            "prioritized_issues": [
                {{
                    "category": "Issue category",
                    "description": "Issue description",
                    "impact": "Potential impact",
                    "priority": "High/Medium/Low",
                    "recommendations": ["Recommendation 1", "Recommendation 2", ...]
                }},
                ...
            ],
            "overall_assessment": "Overall assessment of the AWS environment",
            "cost_implications": "Description of cost implications",
            "performance_implications": "Description of performance implications",
            "security_implications": "Description of security implications",
            "next_steps": ["Step 1", "Step 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Trusted Advisor Agent",
            "analysis": analysis,
            "raw_data": issues_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def get_optimization_recommendations(self) -> Dict[str, Any]:
        """
        Get optimization recommendations based on AWS Trusted Advisor checks.
        
        Returns:
            Dictionary containing optimization recommendations
        """
        # Get Trusted Advisor checks and summaries
        checks_data = self.trusted_advisor.get_trusted_advisor_checks()
        
        if checks_data["status"] != "success":
            return checks_data
        
        summaries_data = self.trusted_advisor.get_trusted_advisor_check_summaries()
        
        if summaries_data["status"] != "success":
            return summaries_data
        
        # Combine checks and summaries
        combined_data = {
            "checks": checks_data["checks"],
            "summaries": summaries_data["summaries"]
        }
        
        # Prepare data for the model
        prompt = f"""
        You are an AWS optimization expert analyzing AWS Trusted Advisor checks and summaries.
        
        Here is the summary of the AWS Trusted Advisor checks:
        - Total checks: {checks_data["check_count"]}
        
        Here are the detailed checks and their summaries:
        {json.dumps(combined_data, indent=2)}
        
        Please analyze these checks and provide:
        1. A summary of the key optimization opportunities
        2. Prioritized recommendations for cost optimization
        3. Prioritized recommendations for performance optimization
        4. Prioritized recommendations for security optimization
        5. Prioritized recommendations for fault tolerance optimization
        6. Overall assessment of the AWS environment optimization status
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of optimization opportunities",
            "cost_optimization": [
                {{
                    "recommendation": "Recommendation description",
                    "potential_savings": "Estimated savings",
                    "effort_level": "High/Medium/Low",
                    "implementation_steps": ["Step 1", "Step 2", ...]
                }},
                ...
            ],
            "performance_optimization": [
                {{
                    "recommendation": "Recommendation description",
                    "potential_impact": "Estimated impact",
                    "effort_level": "High/Medium/Low",
                    "implementation_steps": ["Step 1", "Step 2", ...]
                }},
                ...
            ],
            "security_optimization": [...],
            "fault_tolerance_optimization": [...],
            "overall_assessment": "Overall assessment of optimization status",
            "quick_wins": ["Quick win 1", "Quick win 2", ...],
            "long_term_improvements": ["Improvement 1", "Improvement 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            analysis = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    analysis = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    analysis = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Trusted Advisor Agent",
            "analysis": analysis,
            "raw_data": combined_data,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
