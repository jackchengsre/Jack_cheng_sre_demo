/**
 * Jack Cheng's SRE Copilot with AWS Bedrock
 * 
 * AWS Monitoring Integration Module
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
logger = logging.getLogger('jc-sre-copilot-monitoring')

class CloudTrailIntegration:
    """
    Integration with AWS CloudTrail for monitoring API activity.
    Part of Jack Cheng's SRE Copilot solution.
    """
    
    def __init__(self, region_name='us-east-1'):
        """
        Initialize the CloudTrail integration.
        
        Args:
            region_name (str): AWS region name
        """
        self.region_name = region_name
        self.cloudtrail = boto3.client('cloudtrail', region_name=region_name)
        self.logs = boto3.client('logs', region_name=region_name)
        logger.info(f"CloudTrail integration initialized in region {region_name}")
    
    def get_cloudtrail_logs(self, start_time, end_time, event_names=None, error_codes=None):
        """
        Get CloudTrail logs for the specified time range.
        
        Args:
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            event_names (list): List of event names to filter
            error_codes (list): List of error codes to filter
            
        Returns:
            list: CloudTrail events
        """
        logger.info(f"Getting CloudTrail logs from {start_time} to {end_time}")
        
        # Convert string times to datetime objects
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        # Prepare lookup attributes
        lookup_attributes = []
        if event_names:
            lookup_attributes.append({
                'AttributeKey': 'EventName',
                'AttributeValue': event_names[0]  # Can only filter by one at a time
            })
        if error_codes:
            lookup_attributes.append({
                'AttributeKey': 'ErrorCode',
                'AttributeValue': error_codes[0]  # Can only filter by one at a time
            })
        
        # Get events
        events = []
        next_token = None
        
        while True:
            kwargs = {
                'StartTime': start_datetime,
                'EndTime': end_datetime,
                'MaxResults': 50
            }
            
            if lookup_attributes:
                kwargs['LookupAttributes'] = [lookup_attributes[0]]  # Can only use one at a time
                
            if next_token:
                kwargs['NextToken'] = next_token
                
            response = self.cloudtrail.lookup_events(**kwargs)
            events.extend(response['Events'])
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        # Additional filtering if multiple event names or error codes
        if event_names and len(event_names) > 1:
            events = [e for e in events if json.loads(e['CloudTrailEvent'])['eventName'] in event_names]
        if error_codes and len(error_codes) > 1:
            events = [e for e in events if json.loads(e['CloudTrailEvent']).get('errorCode') in error_codes]
        
        return events
    
    def get_api_errors(self, start_time, end_time):
        """
        Get API errors from CloudTrail logs.
        
        Args:
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            
        Returns:
            list: API error events
        """
        logger.info(f"Getting API errors from {start_time} to {end_time}")
        
        # Get events with error codes
        events = self.get_cloudtrail_logs(start_time, end_time)
        
        # Filter for events with error codes
        error_events = []
        for event in events:
            cloud_trail_event = json.loads(event['CloudTrailEvent'])
            if 'errorCode' in cloud_trail_event:
                error_events.append(event)
        
        return error_events
    
    def get_throttling_events(self, start_time, end_time):
        """
        Get API throttling events from CloudTrail logs.
        
        Args:
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            
        Returns:
            list: API throttling events
        """
        logger.info(f"Getting API throttling events from {start_time} to {end_time}")
        
        # Get events with throttling error codes
        throttling_error_codes = [
            'ThrottlingException',
            'RequestThrottledException',
            'Throttling',
            'RequestLimitExceeded',
            'TooManyRequestsException'
        ]
        
        events = self.get_cloudtrail_logs(start_time, end_time, error_codes=throttling_error_codes)
        
        return events
    
    def get_service_quota_events(self, start_time, end_time):
        """
        Get service quota exceeded events from CloudTrail logs.
        
        Args:
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            
        Returns:
            list: Service quota exceeded events
        """
        logger.info(f"Getting service quota exceeded events from {start_time} to {end_time}")
        
        # Get events with quota exceeded error codes
        quota_error_codes = [
            'LimitExceededException',
            'QuotaExceededException',
            'ServiceQuotaExceededException'
        ]
        
        events = self.get_cloudtrail_logs(start_time, end_time, error_codes=quota_error_codes)
        
        return events


class VPCFlowLogsIntegration:
    """
    Integration with VPC Flow Logs for monitoring network traffic.
    Part of Jack Cheng's SRE Copilot solution.
    """
    
    def __init__(self, region_name='us-east-1'):
        """
        Initialize the VPC Flow Logs integration.
        
        Args:
            region_name (str): AWS region name
        """
        self.region_name = region_name
        self.logs = boto3.client('logs', region_name=region_name)
        self.ec2 = boto3.client('ec2', region_name=region_name)
        logger.info(f"VPC Flow Logs integration initialized in region {region_name}")
    
    def get_vpc_flow_logs(self, log_group_name, start_time, end_time, filter_pattern=None):
        """
        Get VPC Flow Logs for the specified time range.
        
        Args:
            log_group_name (str): CloudWatch Logs group name
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            filter_pattern (str): Filter pattern for logs
            
        Returns:
            list: VPC Flow Log records
        """
        logger.info(f"Getting VPC Flow Logs from {start_time} to {end_time}")
        
        # Convert string times to datetime objects
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        # Convert datetime to milliseconds since epoch
        start_time_ms = int(start_datetime.timestamp() * 1000)
        end_time_ms = int(end_datetime.timestamp() * 1000)
        
        # Get log events
        events = []
        next_token = None
        
        while True:
            kwargs = {
                'logGroupName': log_group_name,
                'startTime': start_time_ms,
                'endTime': end_time_ms,
                'limit': 10000
            }
            
            if filter_pattern:
                kwargs['filterPattern'] = filter_pattern
                
            if next_token:
                kwargs['nextToken'] = next_token
                
            response = self.logs.filter_log_events(**kwargs)
            events.extend(response['events'])
            
            next_token = response.get('nextToken')
            if not next_token:
                break
        
        # Parse VPC Flow Log records
        parsed_records = []
        for event in events:
            try:
                # VPC Flow Log format varies based on version
                # This handles the default format
                fields = event['message'].split()
                if len(fields) >= 13:  # Basic VPC Flow Log format
                    record = {
                        'version': fields[0],
                        'account_id': fields[1],
                        'interface_id': fields[2],
                        'srcaddr': fields[3],
                        'dstaddr': fields[4],
                        'srcport': fields[5],
                        'dstport': fields[6],
                        'protocol': fields[7],
                        'packets': fields[8],
                        'bytes': fields[9],
                        'start': fields[10],
                        'end': fields[11],
                        'action': fields[12],
                        'log_status': fields[13] if len(fields) > 13 else None
                    }
                    parsed_records.append(record)
            except Exception as e:
                logger.warning(f"Failed to parse VPC Flow Log record: {e}")
        
        return parsed_records
    
    def get_rejected_traffic(self, log_group_name, start_time, end_time):
        """
        Get rejected traffic from VPC Flow Logs.
        
        Args:
            log_group_name (str): CloudWatch Logs group name
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            
        Returns:
            list: Rejected traffic records
        """
        logger.info(f"Getting rejected traffic from {start_time} to {end_time}")
        
        # Get records with REJECT action
        filter_pattern = "REJECT"
        records = self.get_vpc_flow_logs(log_group_name, start_time, end_time, filter_pattern)
        
        return records
    
    def get_traffic_by_port(self, log_group_name, start_time, end_time, port):
        """
        Get traffic for a specific port from VPC Flow Logs.
        
        Args:
            log_group_name (str): CloudWatch Logs group name
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            port (int): Port number
            
        Returns:
            list: Traffic records for the specified port
        """
        logger.info(f"Getting traffic for port {port} from {start_time} to {end_time}")
        
        # Get all records
        records = self.get_vpc_flow_logs(log_group_name, start_time, end_time)
        
        # Filter for records with the specified port
        port_records = [r for r in records if r['srcport'] == str(port) or r['dstport'] == str(port)]
        
        return port_records


class HealthDashboardIntegration:
    """
    Integration with AWS Health Dashboard for monitoring service health.
    Part of Jack Cheng's SRE Copilot solution.
    """
    
    def __init__(self, region_name='us-east-1'):
        """
        Initialize the AWS Health Dashboard integration.
        
        Args:
            region_name (str): AWS region name
        """
        self.region_name = region_name
        self.health = boto3.client('health', region_name=region_name)
        logger.info(f"AWS Health Dashboard integration initialized in region {region_name}")
    
    def get_health_events(self, start_time=None, end_time=None, services=None, regions=None, event_type_codes=None):
        """
        Get AWS Health events for the specified time range.
        
        Args:
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            services (list): List of AWS services to filter
            regions (list): List of AWS regions to filter
            event_type_codes (list): List of event type codes to filter
            
        Returns:
            list: AWS Health events
        """
        logger.info(f"Getting AWS Health events from {start_time} to {end_time}")
        
        # Prepare filter
        event_filter = {}
        
        if start_time or end_time:
            event_filter['lastUpdatedTimes'] = []
            if start_time:
                start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                event_filter['lastUpdatedTimes'].append({
                    'from': start_datetime
                })
            if end_time:
                end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                if 'lastUpdatedTimes' in event_filter and event_filter['lastUpdatedTimes']:
                    event_filter['lastUpdatedTimes'][0]['to'] = end_datetime
                else:
                    event_filter['lastUpdatedTimes'].append({
                        'to': end_datetime
                    })
        
        if services:
            event_filter['services'] = services
            
        if regions:
            event_filter['regions'] = regions
            
        if event_type_codes:
            event_filter['eventTypeCategories'] = event_type_codes
        
        # Get events
        events = []
        next_token = None
        
        while True:
            kwargs = {}
            
            if event_filter:
                kwargs['filter'] = event_filter
                
            if next_token:
                kwargs['nextToken'] = next_token
                
            try:
                response = self.health.describe_events(**kwargs)
                events.extend(response['events'])
                
                next_token = response.get('nextToken')
                if not next_token:
                    break
            except Exception as e:
                logger.warning(f"Failed to get AWS Health events: {e}")
                break
        
        # Get event details
        detailed_events = []
        for event in events:
            try:
                details_response = self.health.describe_event_details(
                    eventArns=[event['arn']]
                )
                if details_response['successfulSet']:
                    event_details = details_response['successfulSet'][0]
                    detailed_events.append({
                        **event,
                        'details': event_details
                    })
                else:
                    detailed_events.append(event)
            except Exception as e:
                logger.warning(f"Failed to get event details for {event['arn']}: {e}")
                detailed_events.append(event)
        
        return detailed_events
    
    def get_service_health(self, service, start_time=None, end_time=None, regions=None):
        """
        Get health events for a specific AWS service.
        
        Args:
            service (str): AWS service name
            start_time (str): Start time in ISO format
            end_time (str): End time in ISO format
            regions (list): List of AWS regions to filter
            
        Returns:
            list: AWS Health events for the specified service
        """
        logger.info(f"Getting health events for service {service}")
        
        events = self.get_health_events(start_time, end_time, [service], regions)
        
        return events


class TrustedAdvisorIntegration:
    """
    Integration with AWS Trusted Advisor for monitoring best practices.
    Part of Jack Cheng's SRE Copilot solution.
    """
    
    def __init__(self, region_name='us-east-1'):
        """
        Initialize the AWS Trusted Advisor integration.
        
        Args:
            region_name (str): AWS region name
        """
        self.region_name = region_name
        self.support = boto3.client('support', region_name=region_name)
        logger.info(f"AWS Trusted Advisor integration initialized in region {region_name}")
    
    def get_trusted_advisor_checks(self, check_ids=None, languages=None):
        """
        Get AWS Trusted Advisor checks.
        
        Args:
            check_ids (list): List of check IDs to filter
            languages (list): List of languages for check descriptions
            
        Returns:
            list: AWS Trusted Advisor checks
        """
        logger.info("Getting AWS Trusted Advisor checks")
        
        try:
            # Get check summaries
            kwargs = {}
            if check_ids:
                kwargs['checkIds'] = check_ids
                
            response = self.support.describe_trusted_advisor_checks(language='en')
            checks = response['checks']
            
            # Get check results
            check_results = []
            for check in checks:
                try:
                    result_response = self.support.describe_trusted_advisor_check_result(
                        checkId=check['id'],
                        language='en'
                    )
                    check_results.append({
                        **check,
                        'result': result_response['result']
                    })
                except Exception as e:
                    logger.warning(f"Failed to get check result for {check['id']}: {e}")
                    check_results.append(check)
            
            return check_results
        except Exception as e:
            logger.error(f"Failed to get AWS Trusted Advisor checks: {e}")
            return []
    
    def get_trusted_advisor_check_summaries(self, check_ids=None):
        """
        Get AWS Trusted Advisor check summaries.
        
        Args:
            check_ids (list): List of check IDs to filter
            
        Returns:
            list: AWS Trusted Advisor check summaries
        """
        logger.info("Getting AWS Trusted Advisor check summaries")
        
        try:
            kwargs = {}
            if check_ids:
                kwargs['checkIds'] = check_ids
                
            response = self.support.describe_trusted_advisor_check_summaries(**kwargs)
            summaries = response['summaries']
            
            return summaries
        except Exception as e:
            logger.error(f"Failed to get AWS Trusted Advisor check summaries: {e}")
            return []
    
    def get_service_limits_checks(self):
        """
        Get AWS Trusted Advisor service limits checks.
        
        Returns:
            list: AWS Trusted Advisor service limits checks
        """
        logger.info("Getting AWS Trusted Advisor service limits checks")
        
        # Get all checks
        checks = self.get_trusted_advisor_checks()
        
        # Filter for service limits checks
        service_limits_checks = [c for c in checks if c['category'] == 'service_limits']
        
        return service_limits_checks
    
    def get_security_checks(self):
        """
        Get AWS Trusted Advisor security checks.
        
        Returns:
            list: AWS Trusted Advisor security checks
        """
        logger.info("Getting AWS Trusted Advisor security checks")
        
        # Get all checks
        checks = self.get_trusted_advisor_checks()
        
        # Filter for security checks
        security_checks = [c for c in checks if c['category'] == 'security']
        
        return security_checks

# Example usage
if __name__ == "__main__":
    # Initialize the CloudTrail integration
    cloudtrail_integration = CloudTrailIntegration()
    
    # Get API errors
    start_time = (datetime.now() - timedelta(days=1)).isoformat() + 'Z'
    end_time = datetime.now().isoformat() + 'Z'
    
    errors = cloudtrail_integration.get_api_errors(start_time, end_time)
    print(f"Found {len(errors)} API errors")
    
    # Initialize the VPC Flow Logs integration
    vpc_flow_logs_integration = VPCFlowLogsIntegration()
    
    # Get rejected traffic
    rejected_traffic = vpc_flow_logs_integration.get_rejected_traffic('vpc-flow-logs', start_time, end_time)
    print(f"Found {len(rejected_traffic)} rejected traffic records")
    
    # Initialize the AWS Health Dashboard integration
    health_integration = HealthDashboardIntegration()
    
    # Get health events
    health_events = health_integration.get_health_events(start_time, end_time)
    print(f"Found {len(health_events)} AWS Health events")
    
    # Initialize the AWS Trusted Advisor integration
    trusted_advisor_integration = TrustedAdvisorIntegration()
    
    # Get service limits checks
    service_limits_checks = trusted_advisor_integration.get_service_limits_checks()
    print(f"Found {len(service_limits_checks)} service limits checks")
