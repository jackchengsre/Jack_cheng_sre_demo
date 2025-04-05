"""
Event Correlation System Module

This module implements a correlation system that analyzes events from different AWS monitoring agents
to identify relationships, patterns, and root causes of issues across multiple AWS services.

The correlation system uses AWS Bedrock foundation models to correlate events from:
- CloudTrail (API activity)
- VPC Flow Logs (network traffic)
- AWS Health Dashboard (service health)
- AWS Trusted Advisor (best practices)

It provides a comprehensive root cause analysis by connecting related events across these services.
"""

import json
import logging
import datetime
import boto3
from typing import Dict, List, Any, Optional, Union

from bedrock_monitoring_agents import (
    CloudTrailAgent,
    VPCFlowLogsAgent,
    HealthDashboardAgent,
    TrustedAdvisorAgent
)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EventCorrelationSystem:
    """System for correlating events from different AWS monitoring agents."""
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """
        Initialize the event correlation system.
        
        Args:
            region_name: AWS region name
            model_id: AWS Bedrock foundation model ID to use
        """
        self.region_name = region_name
        self.model_id = model_id
        self.bedrock_runtime = boto3.client('bedrock-runtime', region_name=region_name)
        
        # Initialize the monitoring agents
        self.cloudtrail_agent = CloudTrailAgent(region_name, model_id)
        self.vpc_flow_logs_agent = VPCFlowLogsAgent(region_name, model_id)
        self.health_dashboard_agent = HealthDashboardAgent(region_name, model_id)
        self.trusted_advisor_agent = TrustedAdvisorAgent(region_name, model_id)
        
        logger.info(f"Initialized event correlation system with model {model_id} in region {region_name}")
    
    def _invoke_model(self, prompt: str, max_tokens: int = 4096) -> str:
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
    
    def correlate_events(self, 
                        start_time: Optional[Union[datetime.datetime, str]] = None,
                        end_time: Optional[Union[datetime.datetime, str]] = None,
                        vpc_flow_log_group: Optional[str] = None) -> Dict[str, Any]:
        """
        Correlate events from different AWS monitoring agents to identify relationships and root causes.
        
        Args:
            start_time: Start time for the analysis (default: 24 hours ago)
            end_time: End time for the analysis (default: now)
            vpc_flow_log_group: CloudWatch Logs group name for VPC Flow Logs (optional)
            
        Returns:
            Dictionary containing correlation results
        """
        # Set default time range if not provided
        if not end_time:
            end_time = datetime.datetime.now()
        if not start_time:
            start_time = end_time - datetime.timedelta(hours=24)
        
        # Convert to datetime objects if strings
        if isinstance(start_time, str):
            start_time = datetime.datetime.fromisoformat(start_time)
        if isinstance(end_time, str):
            end_time = datetime.datetime.fromisoformat(end_time)
        
        logger.info(f"Correlating events from {start_time} to {end_time}")
        
        # Collect data from each agent
        results = {}
        
        # CloudTrail API errors
        cloudtrail_errors = self.cloudtrail_agent.analyze_api_errors(
            start_time=start_time,
            end_time=end_time
        )
        results["cloudtrail_errors"] = cloudtrail_errors
        
        # CloudTrail unusual activity
        cloudtrail_activity = self.cloudtrail_agent.detect_unusual_api_activity(
            start_time=start_time,
            end_time=end_time
        )
        results["cloudtrail_activity"] = cloudtrail_activity
        
        # VPC Flow Logs rejected traffic (if log group provided)
        if vpc_flow_log_group:
            vpc_rejected = self.vpc_flow_logs_agent.analyze_rejected_traffic(
                log_group_name=vpc_flow_log_group,
                start_time=start_time,
                end_time=end_time
            )
            results["vpc_rejected"] = vpc_rejected
            
            vpc_anomalies = self.vpc_flow_logs_agent.detect_network_anomalies(
                log_group_name=vpc_flow_log_group,
                start_time=start_time,
                end_time=end_time
            )
            results["vpc_anomalies"] = vpc_anomalies
        
        # AWS Health Dashboard
        health_events = self.health_dashboard_agent.analyze_service_health(
            start_time=start_time,
            end_time=end_time
        )
        results["health_events"] = health_events
        
        # AWS Trusted Advisor
        trusted_advisor_issues = self.trusted_advisor_agent.analyze_trusted_advisor_issues()
        results["trusted_advisor_issues"] = trusted_advisor_issues
        
        # Prepare data for correlation
        correlation_data = {
            "time_range": {
                "start_time": self._format_timestamp(start_time),
                "end_time": self._format_timestamp(end_time)
            },
            "agent_results": {}
        }
        
        # Extract analysis results from each agent
        for key, result in results.items():
            if result["status"] == "success" and "analysis" in result:
                correlation_data["agent_results"][key] = result["analysis"]
        
        # Prepare prompt for correlation
        prompt = f"""
        You are an AWS SRE expert correlating events from different AWS monitoring systems to identify relationships, patterns, and root causes of issues.
        
        Here are the analysis results from different AWS monitoring agents for the time period from {start_time} to {end_time}:
        
        {json.dumps(correlation_data, indent=2)}
        
        Please analyze these results and provide:
        1. A comprehensive correlation of events across different AWS services
        2. Identification of potential root causes for any issues detected
        3. Assessment of the relationships between different events
        4. Timeline of related events and their progression
        5. Overall impact assessment and severity
        6. Recommendations for resolving the identified issues
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief summary of the correlation analysis",
            "correlated_events": [
                {{
                    "event_group": "Name for this group of related events",
                    "related_events": [
                        {{
                            "source": "Source of the event (e.g., CloudTrail, VPC Flow Logs)",
                            "event_type": "Type of event",
                            "description": "Description of the event",
                            "timestamp": "Estimated time of the event"
                        }},
                        ...
                    ],
                    "root_cause": "Identified root cause",
                    "impact": "Impact of these events",
                    "severity": "High/Medium/Low",
                    "recommendations": ["Recommendation 1", "Recommendation 2", ...]
                }},
                ...
            ],
            "overall_assessment": "Overall assessment of the AWS environment",
            "primary_issues": ["Issue 1", "Issue 2", ...],
            "priority_recommendations": ["Recommendation 1", "Recommendation 2", ...],
            "timeline": [
                {{
                    "timestamp": "Time of event",
                    "event": "Description of event",
                    "significance": "Significance of this event"
                }},
                ...
            ]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt)
        
        # Parse the JSON response
        try:
            correlation = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    correlation = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    correlation = {
                        "summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                correlation = {
                    "summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Event Correlation System",
            "correlation": correlation,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def analyze_root_cause(self, 
                          incident_description: str,
                          start_time: Optional[Union[datetime.datetime, str]] = None,
                          end_time: Optional[Union[datetime.datetime, str]] = None,
                          vpc_flow_log_group: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze the root cause of a specific incident using data from multiple monitoring agents.
        
        Args:
            incident_description: Description of the incident to analyze
            start_time: Start time for the analysis (default: 24 hours ago)
            end_time: End time for the analysis (default: now)
            vpc_flow_log_group: CloudWatch Logs group name for VPC Flow Logs (optional)
            
        Returns:
            Dictionary containing root cause analysis results
        """
        # First, correlate events from all agents
        correlation_results = self.correlate_events(
            start_time=start_time,
            end_time=end_time,
            vpc_flow_log_group=vpc_flow_log_group
        )
        
        if correlation_results["status"] != "success":
            return correlation_results
        
        # Prepare prompt for root cause analysis
        prompt = f"""
        You are an AWS SRE expert performing root cause analysis for a specific incident.
        
        Incident Description:
        {incident_description}
        
        Here are the correlated events from different AWS monitoring systems for the relevant time period:
        
        {json.dumps(correlation_results["correlation"], indent=2)}
        
        Please perform a detailed root cause analysis and provide:
        1. Identification of the primary root cause of the incident
        2. Contributing factors that led to or exacerbated the incident
        3. Timeline of events leading up to and during the incident
        4. Impact assessment on different services and components
        5. Detailed recommendations for preventing similar incidents in the future
        6. Lessons learned from this incident
        
        Format your response as JSON with the following structure:
        {{
            "incident_summary": "Brief summary of the incident",
            "root_cause": {{
                "primary_cause": "Primary root cause",
                "description": "Detailed description of the root cause",
                "technical_details": "Technical details of what went wrong",
                "trigger": "What triggered the incident"
            }},
            "contributing_factors": [
                {{
                    "factor": "Contributing factor",
                    "description": "Description of how this factor contributed",
                    "significance": "High/Medium/Low"
                }},
                ...
            ],
            "timeline": [
                {{
                    "timestamp": "Time of event",
                    "event": "Description of event",
                    "significance": "Significance of this event"
                }},
                ...
            ],
            "impact": {{
                "services_affected": ["Service 1", "Service 2", ...],
                "duration": "Duration of the impact",
                "severity": "High/Medium/Low",
                "business_impact": "Description of business impact"
            }},
            "recommendations": [
                {{
                    "recommendation": "Recommendation",
                    "category": "Prevention/Detection/Mitigation/Process",
                    "priority": "High/Medium/Low",
                    "implementation": "Implementation details"
                }},
                ...
            ],
            "lessons_learned": ["Lesson 1", "Lesson 2", ...]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt, max_tokens=4096)
        
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
                        "incident_summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                analysis = {
                    "incident_summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Root Cause Analysis",
            "incident_description": incident_description,
            "analysis": analysis,
            "correlation_data": correlation_results["correlation"],
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
    
    def generate_incident_report(self, root_cause_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive incident report based on root cause analysis results.
        
        Args:
            root_cause_analysis: Root cause analysis results from analyze_root_cause method
            
        Returns:
            Dictionary containing the incident report
        """
        if root_cause_analysis["status"] != "success":
            return root_cause_analysis
        
        # Prepare prompt for incident report
        prompt = f"""
        You are an AWS SRE expert generating a comprehensive incident report based on root cause analysis.
        
        Here is the root cause analysis:
        
        {json.dumps(root_cause_analysis["analysis"], indent=2)}
        
        Please generate a comprehensive incident report that includes:
        1. Executive summary of the incident
        2. Detailed description of the incident
        3. Timeline of events
        4. Root cause analysis
        5. Impact assessment
        6. Resolution and recovery actions
        7. Preventive measures and recommendations
        8. Lessons learned
        9. Action items with owners and deadlines
        
        Format your response as JSON with the following structure:
        {{
            "title": "Incident Report: [Incident Title]",
            "incident_id": "INC-[YYYYMMDD]-[Number]",
            "date": "Date of the incident",
            "status": "Resolved/Ongoing",
            "severity": "Critical/High/Medium/Low",
            "executive_summary": "Brief executive summary",
            "incident_details": {{
                "description": "Detailed description",
                "detection": "How the incident was detected",
                "duration": "Duration of the incident",
                "affected_services": ["Service 1", "Service 2", ...],
                "affected_regions": ["Region 1", "Region 2", ...]
            }},
            "timeline": [
                {{
                    "timestamp": "Time of event",
                    "event": "Description of event",
                    "actor": "Person or system that performed the action"
                }},
                ...
            ],
            "root_cause": {{
                "summary": "Summary of root cause",
                "technical_details": "Technical details",
                "contributing_factors": ["Factor 1", "Factor 2", ...]
            }},
            "impact": {{
                "service_impact": "Description of service impact",
                "customer_impact": "Description of customer impact",
                "business_impact": "Description of business impact",
                "metrics": {{
                    "downtime": "Duration of downtime",
                    "error_rate": "Peak error rate",
                    "affected_customers": "Number of affected customers"
                }}
            }},
            "resolution": {{
                "actions_taken": ["Action 1", "Action 2", ...],
                "resolution_time": "Time to resolve",
                "verification": "How resolution was verified"
            }},
            "preventive_measures": [
                {{
                    "recommendation": "Recommendation",
                    "category": "Technical/Process/Monitoring/Training",
                    "priority": "High/Medium/Low",
                    "estimated_effort": "Estimated effort to implement"
                }},
                ...
            ],
            "lessons_learned": ["Lesson 1", "Lesson 2", ...],
            "action_items": [
                {{
                    "item": "Action item description",
                    "owner": "Owner name or team",
                    "deadline": "Deadline",
                    "status": "Not Started/In Progress/Completed",
                    "priority": "High/Medium/Low"
                }},
                ...
            ]
        }}
        """
        
        # Invoke the model
        model_response = self._invoke_model(prompt, max_tokens=4096)
        
        # Parse the JSON response
        try:
            report = json.loads(model_response)
        except json.JSONDecodeError:
            # If the response is not valid JSON, extract it from the text
            try:
                # Try to find JSON block in the response
                json_start = model_response.find('{')
                json_end = model_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = model_response[json_start:json_end]
                    report = json.loads(json_str)
                else:
                    # Fallback to a simple structure
                    report = {
                        "title": "Incident Report",
                        "executive_summary": "Could not parse model response as JSON",
                        "raw_response": model_response
                    }
            except Exception:
                report = {
                    "title": "Incident Report",
                    "executive_summary": "Could not parse model response as JSON",
                    "raw_response": model_response
                }
        
        return {
            "status": "success",
            "service": "Incident Report Generator",
            "report": report,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }
