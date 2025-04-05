"""
Root Cause Analysis Integration Module

This module integrates the AWS monitoring agents, event correlation system, and test data generator
to provide a comprehensive root cause analysis solution for AWS environments.

It demonstrates how to use AWS Bedrock foundation models to analyze logs, metrics, and dashboards
from multiple AWS services to identify the root cause of incidents.
"""

import json
import logging
import datetime
import os
from typing import Dict, List, Any, Optional, Union

from aws_monitoring_integration import (
    CloudTrailIntegration,
    VPCFlowLogsIntegration,
    HealthDashboardIntegration,
    TrustedAdvisorIntegration
)

from bedrock_monitoring_agents import (
    CloudTrailAgent,
    VPCFlowLogsAgent,
    HealthDashboardAgent,
    TrustedAdvisorAgent
)

from event_correlation_system import EventCorrelationSystem
from test_data_generator import TestDataGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RootCauseAnalysisSystem:
    """
    Integrated system for root cause analysis using AWS Bedrock foundation models.
    
    This system combines:
    - AWS monitoring integrations for data collection
    - Specialized AWS Bedrock agents for service-specific analysis
    - Event correlation system for cross-service analysis
    - Test data generation for demonstration
    """
    
    def __init__(self, region_name: str = 'us-east-1', model_id: str = 'anthropic.claude-3-sonnet-20240229-v1:0'):
        """
        Initialize the root cause analysis system.
        
        Args:
            region_name: AWS region name
            model_id: AWS Bedrock foundation model ID to use
        """
        self.region_name = region_name
        self.model_id = model_id
        
        # Initialize the event correlation system (which includes all agents)
        self.correlation_system = EventCorrelationSystem(region_name, model_id)
        
        # Initialize the test data generator
        self.test_data_generator = TestDataGenerator()
        
        # Create output directory for results
        os.makedirs('results', exist_ok=True)
        
        logger.info(f"Initialized root cause analysis system with model {model_id} in region {region_name}")
    
    def _format_timestamp(self, timestamp: datetime.datetime) -> str:
        """Format timestamp to ISO 8601 string."""
        if isinstance(timestamp, datetime.datetime):
            return timestamp.isoformat()
        return timestamp
    
    def analyze_with_test_data(self) -> Dict[str, Any]:
        """
        Perform root cause analysis using generated test data.
        
        Returns:
            Dictionary containing analysis results
        """
        logger.info("Generating test data for root cause analysis")
        
        # Generate test data
        incident_data = self.test_data_generator.generate_correlated_incident_data()
        incident_description = self.test_data_generator.generate_incident_description()
        
        # Save test data to files
        self._save_test_data(incident_data, incident_description)
        
        # Perform root cause analysis
        analysis_results = self._analyze_incident(incident_data, incident_description)
        
        # Save analysis results
        self._save_analysis_results(analysis_results)
        
        return analysis_results
    
    def _save_test_data(self, incident_data: Dict[str, Any], incident_description: str) -> None:
        """
        Save test data to files.
        
        Args:
            incident_data: Generated incident data
            incident_description: Incident description
        """
        # Save individual data files
        with open('results/test_data_cloudtrail.json', 'w') as f:
            json.dump(incident_data["cloudtrail_errors"], f, indent=2)
        
        with open('results/test_data_vpc_flow_logs.json', 'w') as f:
            json.dump(incident_data["vpc_flow_logs"], f, indent=2)
        
        with open('results/test_data_health_events.json', 'w') as f:
            json.dump(incident_data["health_events"], f, indent=2)
        
        with open('results/test_data_trusted_advisor.json', 'w') as f:
            json.dump(incident_data["trusted_advisor_issues"], f, indent=2)
        
        # Save combined incident data
        with open('results/test_data_incident.json', 'w') as f:
            json.dump(incident_data, f, indent=2)
        
        # Save incident description
        with open('results/test_data_incident_description.txt', 'w') as f:
            f.write(incident_description)
        
        logger.info("Test data saved to results directory")
    
    def _analyze_incident(self, incident_data: Dict[str, Any], incident_description: str) -> Dict[str, Any]:
        """
        Analyze an incident using the event correlation system.
        
        Args:
            incident_data: Incident data from different AWS services
            incident_description: Description of the incident
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info("Analyzing incident with event correlation system")
        
        # Extract time range from incident data
        timeline = incident_data.get("incident_timeline", {})
        quota_exceeded_time = timeline.get("quota_exceeded_time")
        service_quota_event_time = timeline.get("service_quota_event_time")
        
        # Convert to datetime objects if strings
        if isinstance(quota_exceeded_time, str):
            quota_exceeded_time = datetime.datetime.fromisoformat(quota_exceeded_time)
        if isinstance(service_quota_event_time, str):
            service_quota_event_time = datetime.datetime.fromisoformat(service_quota_event_time)
        
        # Set time range for analysis
        if service_quota_event_time:
            start_time = service_quota_event_time - datetime.timedelta(hours=1)
        else:
            # Default to 24 hours ago
            start_time = datetime.datetime.now() - datetime.timedelta(hours=24)
        
        end_time = datetime.datetime.now()
        
        # Mock the correlation system to use test data instead of real AWS API calls
        # This is done by monkey patching the agent methods
        
        # Store original methods
        original_cloudtrail_analyze = self.correlation_system.cloudtrail_agent.analyze_api_errors
        original_cloudtrail_detect = self.correlation_system.cloudtrail_agent.detect_unusual_api_activity
        original_vpc_analyze = self.correlation_system.vpc_flow_logs_agent.analyze_rejected_traffic
        original_vpc_detect = self.correlation_system.vpc_flow_logs_agent.detect_network_anomalies
        original_health_analyze = self.correlation_system.health_dashboard_agent.analyze_service_health
        original_trusted_analyze = self.correlation_system.trusted_advisor_agent.analyze_trusted_advisor_issues
        
        # Replace with mock methods that return test data
        def mock_cloudtrail_analyze(*args, **kwargs):
            return {
                "status": "success",
                "service": "CloudTrail Agent",
                "analysis": self._extract_analysis(incident_data["cloudtrail_errors"]),
                "raw_data": incident_data["cloudtrail_errors"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        def mock_cloudtrail_detect(*args, **kwargs):
            return {
                "status": "success",
                "service": "CloudTrail Agent",
                "analysis": self._extract_analysis(incident_data["cloudtrail_errors"]),
                "raw_data": incident_data["cloudtrail_errors"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        def mock_vpc_analyze(*args, **kwargs):
            return {
                "status": "success",
                "service": "VPC Flow Logs Agent",
                "analysis": self._extract_analysis(incident_data["vpc_flow_logs"]),
                "raw_data": incident_data["vpc_flow_logs"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        def mock_vpc_detect(*args, **kwargs):
            return {
                "status": "success",
                "service": "VPC Flow Logs Agent",
                "analysis": self._extract_analysis(incident_data["vpc_flow_logs"]),
                "raw_data": incident_data["vpc_flow_logs"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        def mock_health_analyze(*args, **kwargs):
            return {
                "status": "success",
                "service": "Health Dashboard Agent",
                "analysis": self._extract_analysis(incident_data["health_events"]),
                "raw_data": incident_data["health_events"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        def mock_trusted_analyze(*args, **kwargs):
            return {
                "status": "success",
                "service": "Trusted Advisor Agent",
                "analysis": self._extract_analysis(incident_data["trusted_advisor_issues"]),
                "raw_data": incident_data["trusted_advisor_issues"],
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
        
        # Apply monkey patches
        self.correlation_system.cloudtrail_agent.analyze_api_errors = mock_cloudtrail_analyze
        self.correlation_system.cloudtrail_agent.detect_unusual_api_activity = mock_cloudtrail_detect
        self.correlation_system.vpc_flow_logs_agent.analyze_rejected_traffic = mock_vpc_analyze
        self.correlation_system.vpc_flow_logs_agent.detect_network_anomalies = mock_vpc_detect
        self.correlation_system.health_dashboard_agent.analyze_service_health = mock_health_analyze
        self.correlation_system.trusted_advisor_agent.analyze_trusted_advisor_issues = mock_trusted_analyze
        
        try:
            # Perform root cause analysis
            analysis_results = self.correlation_system.analyze_root_cause(
                incident_description=incident_description,
                start_time=start_time,
                end_time=end_time,
                vpc_flow_log_group="vpc-flow-logs"  # This is ignored in mock mode
            )
            
            # Generate incident report
            report_results = self.correlation_system.generate_incident_report(analysis_results)
            
            # Combine results
            combined_results = {
                "root_cause_analysis": analysis_results,
                "incident_report": report_results,
                "timestamp": self._format_timestamp(datetime.datetime.now())
            }
            
            return combined_results
            
        finally:
            # Restore original methods
            self.correlation_system.cloudtrail_agent.analyze_api_errors = original_cloudtrail_analyze
            self.correlation_system.cloudtrail_agent.detect_unusual_api_activity = original_cloudtrail_detect
            self.correlation_system.vpc_flow_logs_agent.analyze_rejected_traffic = original_vpc_analyze
            self.correlation_system.vpc_flow_logs_agent.detect_network_anomalies = original_vpc_detect
            self.correlation_system.health_dashboard_agent.analyze_service_health = original_health_analyze
            self.correlation_system.trusted_advisor_agent.analyze_trusted_advisor_issues = original_trusted_analyze
    
    def _extract_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract analysis-relevant fields from test data.
        
        Args:
            data: Test data dictionary
            
        Returns:
            Dictionary containing analysis-relevant fields
        """
        # This is a simplified version that would normally be replaced by actual agent analysis
        if "cloudtrail_errors" in data:
            # This is the combined incident data
            return {
                "summary": "Analysis of CloudTrail errors",
                "error_count": data["cloudtrail_errors"].get("error_event_count", 0),
                "throttle_count": data["cloudtrail_errors"].get("throttle_event_count", 0)
            }
        elif "error_events" in data:
            # This is CloudTrail data
            return {
                "summary": "Analysis of CloudTrail logs",
                "error_count": data.get("error_event_count", 0),
                "throttle_count": data.get("throttle_event_count", 0),
                "patterns": ["EC2 quota exceeded errors", "API throttling for EC2 operations"]
            }
        elif "rejected_events" in data:
            # This is VPC Flow Logs data
            return {
                "summary": "Analysis of VPC Flow Logs",
                "rejected_count": data.get("rejected_event_count", 0),
                "patterns": ["Rejected SSH connections", "Port scanning activity"]
            }
        elif "active_events" in data:
            # This is Health Dashboard data
            return {
                "summary": "Analysis of AWS Health Dashboard",
                "active_count": data.get("active_event_count", 0),
                "affected_services": list(data.get("service_summary", {}).keys())
            }
        elif "issues" in data:
            # This is Trusted Advisor data
            return {
                "summary": "Analysis of AWS Trusted Advisor",
                "issue_count": data.get("issue_count", 0),
                "categories": list(set(issue.get("category") for issue in data.get("issues", [])))
            }
        else:
            return {
                "summary": "Could not determine data type for analysis",
                "raw_data": data
            }
    
    def _save_analysis_results(self, analysis_results: Dict[str, Any]) -> None:
        """
        Save analysis results to files.
        
        Args:
            analysis_results: Analysis results
        """
        # Save root cause analysis
        with open('results/root_cause_analysis.json', 'w') as f:
            json.dump(analysis_results["root_cause_analysis"], f, indent=2)
        
        # Save incident report
        with open('results/incident_report.json', 'w') as f:
            json.dump(analysis_results["incident_report"], f, indent=2)
        
        # Save combined results
        with open('results/analysis_results.json', 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        logger.info("Analysis results saved to results directory")
    
    def run_demonstration(self) -> Dict[str, Any]:
        """
        Run a complete demonstration of the root cause analysis system.
        
        Returns:
            Dictionary containing demonstration results
        """
        logger.info("Starting root cause analysis demonstration")
        
        # Analyze with test data
        analysis_results = self.analyze_with_test_data()
        
        # Generate a summary of the demonstration
        summary = {
            "demonstration_id": f"demo-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": self._format_timestamp(datetime.datetime.now()),
            "components_demonstrated": [
                "AWS CloudTrail monitoring",
                "VPC Flow Logs monitoring",
                "AWS Health Dashboard monitoring",
                "AWS Trusted Advisor monitoring",
                "Event correlation across services",
                "Root cause analysis",
                "Incident reporting"
            ],
            "files_generated": [
                "results/test_data_cloudtrail.json",
                "results/test_data_vpc_flow_logs.json",
                "results/test_data_health_events.json",
                "results/test_data_trusted_advisor.json",
                "results/test_data_incident.json",
                "results/test_data_incident_description.txt",
                "results/root_cause_analysis.json",
                "results/incident_report.json",
                "results/analysis_results.json"
            ],
            "root_cause_summary": analysis_results["root_cause_analysis"]["analysis"].get("root_cause", {}).get("primary_cause", "Unknown"),
            "incident_title": analysis_results["incident_report"]["report"].get("title", "Untitled Incident")
        }
        
        # Save summary
        with open('results/demonstration_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Demonstration completed: {summary['incident_title']}")
        
        return {
            "status": "success",
            "service": "Root Cause Analysis Demonstration",
            "summary": summary,
            "analysis_results": analysis_results,
            "timestamp": self._format_timestamp(datetime.datetime.now())
        }


def main():
    """Run the root cause analysis demonstration."""
    # Initialize the system
    rca_system = RootCauseAnalysisSystem()
    
    # Run the demonstration
    results = rca_system.run_demonstration()
    
    # Print a summary
    print(f"Demonstration completed: {results['summary']['incident_title']}")
    print(f"Root cause: {results['summary']['root_cause_summary']}")
    print(f"Files generated: {len(results['summary']['files_generated'])}")
    print("See the 'results' directory for all generated files.")


if __name__ == "__main__":
    main()
