"""
Test Data Generator for AWS Monitoring and Root Cause Analysis

This module generates synthetic test data for demonstrating the AWS monitoring
and root cause analysis capabilities of the SRE copilot.

It creates realistic test data for:
- CloudTrail logs with API errors and throttling events
- VPC Flow Logs with rejected traffic patterns
- AWS Health Dashboard events
- AWS Trusted Advisor issues

The generated data can be used to showcase the monitoring agents and event correlation system.
"""

import json
import random
import datetime
import uuid
from typing import Dict, List, Any, Optional, Union

class TestDataGenerator:
    """Generator for synthetic AWS monitoring test data."""
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the test data generator.
        
        Args:
            seed: Random seed for reproducible data generation
        """
        if seed is not None:
            random.seed(seed)
        
        self.current_time = datetime.datetime.now()
        self.account_id = "123456789012"
        self.region = "us-east-1"
        
        # Common AWS services for generating events
        self.aws_services = [
            "ec2", "s3", "rds", "lambda", "dynamodb", 
            "cloudwatch", "iam", "sqs", "sns", "apigateway"
        ]
        
        # Common API actions for each service
        self.service_actions = {
            "ec2": ["DescribeInstances", "RunInstances", "TerminateInstances", "CreateSecurityGroup", "AuthorizeSecurityGroupIngress"],
            "s3": ["GetObject", "PutObject", "ListBucket", "CreateBucket", "DeleteObject"],
            "rds": ["DescribeDBInstances", "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance", "RestoreDBInstanceFromSnapshot"],
            "lambda": ["Invoke", "CreateFunction", "UpdateFunctionCode", "DeleteFunction", "GetFunction"],
            "dynamodb": ["GetItem", "PutItem", "Query", "Scan", "UpdateItem"],
            "cloudwatch": ["PutMetricData", "GetMetricData", "DescribeAlarms", "PutDashboard", "GetDashboard"],
            "iam": ["CreateRole", "AttachRolePolicy", "GetRole", "ListRoles", "DeleteRole"],
            "sqs": ["SendMessage", "ReceiveMessage", "DeleteMessage", "CreateQueue", "DeleteQueue"],
            "sns": ["Publish", "Subscribe", "Unsubscribe", "CreateTopic", "DeleteTopic"],
            "apigateway": ["CreateApi", "GetApi", "CreateRoute", "GetRoutes", "DeleteApi"]
        }
        
        # Common error codes
        self.error_codes = [
            "AccessDenied", "ThrottlingException", "ValidationError", 
            "ResourceNotFoundException", "InvalidParameterValue",
            "ServiceUnavailable", "InternalFailure", "LimitExceededException"
        ]
        
        # IP addresses for VPC Flow Logs
        self.internal_ips = [
            "10.0.0.5", "10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.25",
            "172.16.0.5", "172.16.0.10", "172.16.0.15", "172.16.0.20", "172.16.0.25"
        ]
        
        self.external_ips = [
            "54.23.45.67", "18.234.123.45", "35.162.78.90", "52.87.123.45", "34.215.67.89",
            "203.0.113.5", "198.51.100.10", "192.0.2.15", "198.51.100.20", "203.0.113.25"
        ]
        
        # Common ports
        self.common_ports = {
            "http": 80,
            "https": 443,
            "ssh": 22,
            "mysql": 3306,
            "postgresql": 5432,
            "redis": 6379,
            "mongodb": 27017,
            "smtp": 25,
            "dns": 53,
            "ntp": 123
        }
        
        # AWS Health event types
        self.health_event_types = [
            "AWS_EC2_INSTANCE_STORE_DRIVE_PERFORMANCE_DEGRADED",
            "AWS_EC2_INSTANCE_LAUNCH_FAILURE",
            "AWS_RDS_STORAGE_CAPACITY_ISSUE",
            "AWS_ELASTICLOADBALANCING_API_ISSUE",
            "AWS_ROUTE53_ZONE_AVAILABILITY_ISSUE",
            "AWS_CLOUDFRONT_DISTRIBUTION_LATENCY_ISSUE",
            "AWS_S3_BUCKET_ACCESS_ISSUE",
            "AWS_DYNAMODB_THROUGHPUT_ISSUE",
            "AWS_LAMBDA_EXECUTION_ISSUE",
            "AWS_API_GATEWAY_ENDPOINT_ISSUE"
        ]
        
        # Trusted Advisor check categories
        self.trusted_advisor_categories = [
            "cost_optimizing", "performance", "security", "fault_tolerance", "service_limits"
        ]
        
        # Trusted Advisor checks
        self.trusted_advisor_checks = {
            "cost_optimizing": [
                "Low Utilization Amazon EC2 Instances",
                "Underutilized Amazon EBS Volumes",
                "Idle Load Balancers",
                "Unassociated Elastic IP Addresses",
                "Amazon RDS Idle DB Instances"
            ],
            "performance": [
                "High Utilization Amazon EC2 Instances",
                "Large Number of EC2 Security Group Rules",
                "Large Number of Rules in an EC2 Security Group",
                "High Utilization Amazon RDS DB Instances",
                "CloudFront Content Delivery Optimization"
            ],
            "security": [
                "Security Groups - Specific Ports Unrestricted",
                "Security Groups - Unrestricted Access",
                "IAM Use",
                "Amazon S3 Bucket Permissions",
                "Exposed Access Keys"
            ],
            "fault_tolerance": [
                "Amazon EBS Snapshots",
                "Amazon RDS Backups",
                "Amazon S3 Bucket Versioning",
                "Amazon EC2 Availability Zone Balance",
                "Load Balancer Optimization"
            ],
            "service_limits": [
                "VPC Limits",
                "EC2 On-Demand Instances",
                "RDS DB Instances",
                "EBS Active Volumes",
                "Lambda Concurrent Executions"
            ]
        }
    
    def _random_timestamp(self, hours_ago: int = 24) -> datetime.datetime:
        """Generate a random timestamp within the past N hours."""
        seconds_ago = random.randint(0, hours_ago * 3600)
        return self.current_time - datetime.timedelta(seconds=seconds_ago)
    
    def _format_timestamp(self, timestamp: datetime.datetime) -> str:
        """Format timestamp to ISO 8601 string."""
        return timestamp.isoformat()
    
    def generate_cloudtrail_events(self, 
                                  count: int = 100, 
                                  error_percentage: float = 0.2,
                                  throttle_percentage: float = 0.1) -> Dict[str, Any]:
        """
        Generate synthetic CloudTrail events with errors and throttling.
        
        Args:
            count: Number of events to generate
            error_percentage: Percentage of events that should have errors
            throttle_percentage: Percentage of events that should have throttling errors
            
        Returns:
            Dictionary containing CloudTrail events
        """
        events = []
        error_events = []
        throttle_events = []
        access_denied_events = []
        
        for _ in range(count):
            # Select a random service and action
            service = random.choice(self.aws_services)
            action = random.choice(self.service_actions[service])
            
            # Generate a random timestamp
            timestamp = self._random_timestamp()
            
            # Generate a random source IP
            source_ip = random.choice(self.external_ips)
            
            # Generate a random user
            user_types = ["IAMUser", "AssumedRole", "FederatedUser", "Root"]
            user_type = random.choice(user_types)
            
            if user_type == "IAMUser":
                username = f"user-{random.randint(1, 5)}"
            elif user_type == "AssumedRole":
                username = f"role-{random.randint(1, 3)}/session-{random.randint(1000, 9999)}"
            elif user_type == "FederatedUser":
                username = f"federated-user-{random.randint(1, 3)}"
            else:
                username = "root"
            
            # Create the base event
            event = {
                'event_id': str(uuid.uuid4()),
                'event_name': action,
                'event_time': self._format_timestamp(timestamp),
                'username': username,
                'resources': [],
                'source_ip_address': source_ip,
                'aws_region': self.region,
                'error_code': None,
                'error_message': None,
                'request_parameters': {
                    'service': service
                },
                'response_elements': {},
                'read_only': action.startswith("Describe") or action.startswith("Get") or action.startswith("List"),
                'event_type': "AwsApiCall",
                'event_source': f"{service}.amazonaws.com"
            }
            
            # Determine if this should be an error event
            is_error = random.random() < error_percentage
            is_throttle = random.random() < (throttle_percentage / error_percentage) if is_error else False
            is_access_denied = random.random() < 0.5 if is_error and not is_throttle else False
            
            if is_error:
                if is_throttle:
                    event['error_code'] = "ThrottlingException"
                    event['error_message'] = f"Rate exceeded for {action}"
                    throttle_events.append(event)
                elif is_access_denied:
                    event['error_code'] = "AccessDenied"
                    event['error_message'] = f"User: {username} is not authorized to perform: {service}:{action}"
                    access_denied_events.append(event)
                else:
                    event['error_code'] = random.choice(self.error_codes)
                    event['error_message'] = f"An error occurred ({event['error_code']}) when calling the {action} operation"
                
                error_events.append(event)
            
            events.append(event)
        
        # Create a pattern of related errors
        # For example, a series of throttling errors for the same service within a short time period
        if throttle_events:
            # Pick a service to have a throttling issue
            problem_service = random.choice(self.aws_services)
            problem_time = self._random_timestamp(hours_ago=4)
            
            # Create a burst of throttling errors
            for i in range(min(15, len(throttle_events))):
                burst_time = problem_time + datetime.timedelta(seconds=i*10)
                throttle_events[i]['event_time'] = self._format_timestamp(burst_time)
                throttle_events[i]['event_source'] = f"{problem_service}.amazonaws.com"
                throttle_events[i]['event_name'] = random.choice(self.service_actions[problem_service])
                throttle_events[i]['error_message'] = f"Rate exceeded for {throttle_events[i]['event_name']}"
        
        return {
            "status": "success",
            "service": "CloudTrail",
            "event_count": len(events),
            "events": events,
            "error_event_count": len(error_events),
            "throttle_event_count": len(throttle_events),
            "access_denied_event_count": len(access_denied_events),
            "error_events": error_events,
            "throttle_events": throttle_events,
            "access_denied_events": access_denied_events,
            "timestamp": self._format_timestamp(self.current_time)
        }
    
    def generate_vpc_flow_logs(self,
                              count: int = 1000,
                              rejected_percentage: float = 0.15) -> Dict[str, Any]:
        """
        Generate synthetic VPC Flow Logs with rejected traffic patterns.
        
        Args:
            count: Number of log entries to generate
            rejected_percentage: Percentage of traffic that should be rejected
            
        Returns:
            Dictionary containing VPC Flow Logs
        """
        events = []
        rejected_events = []
        
        # Generate random VPC Flow Log entries
        for _ in range(count):
            # Generate random source and destination
            is_inbound = random.random() < 0.5
            
            if is_inbound:
                src_addr = random.choice(self.external_ips)
                dst_addr = random.choice(self.internal_ips)
            else:
                src_addr = random.choice(self.internal_ips)
                dst_addr = random.choice(self.external_ips)
            
            # Generate random ports
            port_name = random.choice(list(self.common_ports.keys()))
            port = self.common_ports[port_name]
            
            if is_inbound:
                dst_port = port
                src_port = random.randint(10000, 65000)
            else:
                src_port = port
                dst_port = random.randint(10000, 65000)
            
            # Determine protocol
            protocol_map = {80: 6, 443: 6, 22: 6, 3306: 6, 5432: 6, 6379: 6, 27017: 6, 25: 6, 53: 17, 123: 17}
            protocol = protocol_map.get(port, 6)  # Default to TCP (6)
            
            # Generate timestamp
            timestamp = self._random_timestamp()
            
            # Determine if traffic is accepted or rejected
            is_rejected = random.random() < rejected_percentage
            action = "REJECT" if is_rejected else "ACCEPT"
            
            # Create the flow log entry
            flow_log = {
                'version': '2',
                'account_id': self.account_id,
                'interface_id': f"eni-{random.randint(10000000, 99999999)}",
                'srcaddr': src_addr,
                'dstaddr': dst_addr,
                'srcport': str(src_port),
                'dstport': str(dst_port),
                'protocol': str(protocol),
                'packets': str(random.randint(1, 100)),
                'bytes': str(random.randint(64, 1500) * random.randint(1, 100)),
                'start': str(int(timestamp.timestamp())),
                'end': str(int(timestamp.timestamp()) + random.randint(1, 10)),
                'action': action,
                'log_status': "OK",
                'timestamp': self._format_timestamp(timestamp),
                'protocol_name': "TCP" if protocol == 6 else "UDP" if protocol == 17 else f"PROTOCOL-{protocol}",
                'traffic_allowed': action == "ACCEPT"
            }
            
            events.append(flow_log)
            
            if is_rejected:
                rejected_events.append(flow_log)
        
        # Create patterns of rejected traffic
        # For example, repeated connection attempts to a specific port that are all rejected
        if rejected_events:
            # Create a pattern of SSH brute force attempts
            ssh_target = random.choice(self.internal_ips)
            attacker_ip = random.choice(self.external_ips)
            attack_start_time = self._random_timestamp(hours_ago=6)
            
            # Create a series of rejected SSH connection attempts
            for i in range(min(20, len(rejected_events) // 3)):
                attempt_time = attack_start_time + datetime.timedelta(seconds=i*5)
                rejected_events[i]['srcaddr'] = attacker_ip
                rejected_events[i]['dstaddr'] = ssh_target
                rejected_events[i]['dstport'] = "22"
                rejected_events[i]['protocol'] = "6"  # TCP
                rejected_events[i]['protocol_name'] = "TCP"
                rejected_events[i]['action'] = "REJECT"
                rejected_events[i]['traffic_allowed'] = False
                rejected_events[i]['timestamp'] = self._format_timestamp(attempt_time)
                rejected_events[i]['start'] = str(int(attempt_time.timestamp()))
                rejected_events[i]['end'] = str(int(attempt_time.timestamp()) + 1)
            
            # Create a pattern of port scanning
            scan_target = random.choice(self.internal_ips)
            scanner_ip = random.choice([ip for ip in self.external_ips if ip != attacker_ip])
            scan_start_time = self._random_timestamp(hours_ago=8)
            
            # Create a series of port scan attempts
            scan_ports = [80, 443, 22, 3306, 5432, 8080, 8443, 25, 21, 23]
            for i in range(min(len(scan_ports), len(rejected_events) // 3)):
                scan_time = scan_start_time + datetime.timedelta(seconds=i*2)
                idx = len(rejected_events) // 3 + i
                rejected_events[idx]['srcaddr'] = scanner_ip
                rejected_events[idx]['dstaddr'] = scan_target
                rejected_events[idx]['dstport'] = str(scan_ports[i])
                rejected_events[idx]['protocol'] = "6"  # TCP
                rejected_events[idx]['protocol_name'] = "TCP"
                rejected_events[idx]['action'] = "REJECT"
                rejected_events[idx]['traffic_allowed'] = False
                rejected_events[idx]['timestamp'] = self._format_timestamp(scan_time)
                rejected_events[idx]['start'] = str(int(scan_time.timestamp()))
                rejected_events[idx]['end'] = str(int(scan_time.timestamp()) + 1)
        
        # Group rejected traffic by source, destination, and port
        rejection_patterns = {}
        for event in rejected_events:
            src = event.get('srcaddr', 'unknown')
            dst = event.get('dstaddr', 'unknown')
            dstport = event.get('dstport', 'unknown')
            protocol = event.get('protocol_name', event.get('protocol', 'unknown'))
            
            key = f"{src}->{dst}:{dstport}/{protocol}"
            if key not in rejection_patterns:
                rejection_patterns[key] = {
                    'source_ip': src,
                    'destination_ip': dst,
                    'destination_port': dstport,
                    'protocol': protocol,
                    'count': 0,
                    'first_seen': event.get('timestamp'),
                    'last_seen': event.get('timestamp'),
                    'sample_events': []
                }
            
            rejection_patterns[key]['count'] += 1
            rejection_patterns[key]['last_seen'] = event.get('timestamp')
            
            # Keep a few sample events
            if len(rejection_patterns[key]['sample_events']) < 5:
                rejection_patterns[key]['sample_events'].append(event)
        
        # Convert to list and sort by count
        patterns_list = list(rejection_patterns.values())
        patterns_list.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            "status": "success",
            "service": "VPC Flow Logs",
            "log_group": "vpc-flow-logs",
            "event_count": len(events),
            "events": events,
            "rejected_event_count": len(rejected_events),
            "rejection_pattern_count": len(patterns_list),
            "rejection_patterns": patterns_list,
            "timestamp": self._format_timestamp(self.current_time)
        }
    
    def generate_health_dashboard_events(self, count: int = 10) -> Dict[str, Any]:
        """
        Generate synthetic AWS Health Dashboard events.
        
        Args:
            count: Number of health events to generate
            
        Returns:
            Dictionary containing AWS Health Dashboard events
        """
        events = []
        
        # Generate random health events
        for _ in range(count):
            # Select a random event type
            event_type_code = random.choice(self.health_event_types)
            
            # Determine the service from the event type
            service = event_type_code.split('_')[1].lower()
            
            # Determine the event category
            categories = ["issue", "accountNotification", "scheduledChange", "investigation"]
            category = random.choice(categories)
            
            # Generate timestamps
            start_time = self._random_timestamp(hours_ago=48)
            
            # Determine if the event is still ongoing
            is_ongoing = random.random() < 0.3
            end_time = None if is_ongoing else start_time + datetime.timedelta(hours=random.randint(1, 8))
            
            # Determine the status
            status_options = ["open", "closed", "upcoming"]
            status = "open" if is_ongoing else "closed" if end_time and end_time < self.current_time else "upcoming"
            
            # Generate a random region
            regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1"]
            region = random.choice(regions)
            
            # Create the health event
            event = {
                'arn': f"arn:aws:health:{region}::event/{service}/{event_type_code}/{uuid.uuid4()}",
                'service': service,
                'event_type_code': event_type_code,
                'event_type_category': category,
                'region': region,
                'start_time': self._format_timestamp(start_time),
                'end_time': self._format_timestamp(end_time) if end_time else None,
                'last_updated_time': self._format_timestamp(start_time + datetime.timedelta(hours=random.randint(0, 4))),
                'status_code': status
            }
            
            # Add event description
            descriptions = {
                "AWS_EC2_INSTANCE_STORE_DRIVE_PERFORMANCE_DEGRADED": "We are investigating increased latency and decreased throughput for instance store volumes on a small number of EC2 instances in the affected region.",
                "AWS_EC2_INSTANCE_LAUNCH_FAILURE": "We are investigating an issue impacting instance launches in the affected region. Existing instances are not impacted.",
                "AWS_RDS_STORAGE_CAPACITY_ISSUE": "We are investigating an issue affecting storage capacity allocation for RDS instances in the affected region.",
                "AWS_ELASTICLOADBALANCING_API_ISSUE": "We are investigating increased error rates for Elastic Load Balancing API requests in the affected region.",
                "AWS_ROUTE53_ZONE_AVAILABILITY_ISSUE": "We are investigating an issue affecting a small number of Route 53 hosted zones.",
                "AWS_CLOUDFRONT_DISTRIBUTION_LATENCY_ISSUE": "We are investigating increased latency for some CloudFront distributions.",
                "AWS_S3_BUCKET_ACCESS_ISSUE": "We are investigating increased error rates for S3 bucket operations in the affected region.",
                "AWS_DYNAMODB_THROUGHPUT_ISSUE": "We are investigating throughput degradation for some DynamoDB tables in the affected region.",
                "AWS_LAMBDA_EXECUTION_ISSUE": "We are investigating increased error rates for Lambda function executions in the affected region.",
                "AWS_API_GATEWAY_ENDPOINT_ISSUE": "We are investigating increased latency and error rates for API Gateway endpoints in the affected region."
            }
            
            event['event_description'] = descriptions.get(event_type_code, f"We are investigating an issue with {service} in the {region} region.")
            
            events.append(event)
        
        # Create a pattern of related health events
        # For example, a cascading failure across multiple services
        if len(events) >= 3:
            # Create a cascading failure scenario
            cascade_region = random.choice(["us-east-1", "us-west-2", "eu-west-1"])
            cascade_start_time = self._random_timestamp(hours_ago=12)
            
            # Primary issue: EC2
            events[0]['service'] = "ec2"
            events[0]['event_type_code'] = "AWS_EC2_INSTANCE_STORE_DRIVE_PERFORMANCE_DEGRADED"
            events[0]['region'] = cascade_region
            events[0]['start_time'] = self._format_timestamp(cascade_start_time)
            events[0]['status_code'] = "open"
            events[0]['event_description'] = f"We are investigating increased latency and decreased throughput for instance store volumes in the {cascade_region} region."
            
            # Secondary issue: RDS (30 minutes later)
            events[1]['service'] = "rds"
            events[1]['event_type_code'] = "AWS_RDS_STORAGE_CAPACITY_ISSUE"
            events[1]['region'] = cascade_region
            events[1]['start_time'] = self._format_timestamp(cascade_start_time + datetime.timedelta(minutes=30))
            events[1]['status_code'] = "open"
            events[1]['event_description'] = f"We are investigating an issue affecting storage capacity allocation for RDS instances in the {cascade_region} region."
            
            # Tertiary issue: Lambda (1 hour later)
            events[2]['service'] = "lambda"
            events[2]['event_type_code'] = "AWS_LAMBDA_EXECUTION_ISSUE"
            events[2]['region'] = cascade_region
            events[2]['start_time'] = self._format_timestamp(cascade_start_time + datetime.timedelta(hours=1))
            events[2]['status_code'] = "open"
            events[2]['event_description'] = f"We are investigating increased error rates for Lambda function executions in the {cascade_region} region."
        
        # Group events by service and region
        service_summary = {}
        region_summary = {}
        category_summary = {}
        active_events = []
        
        for event in events:
            service = event.get('service', 'unknown')
            region = event.get('region', 'global')
            category = event.get('event_type_category', 'unknown')
            status = event.get('status_code', 'unknown')
            
            # Track active events
            if status in ['open', 'upcoming']:
                active_events.append(event)
            
            # Update service summary
            if service not in service_summary:
                service_summary[service] = {
                    'total_events': 0,
                    'open_events': 0,
                    'closed_events': 0,
                    'upcoming_events': 0
                }
            
            service_summary[service]['total_events'] += 1
            if status == 'open':
                service_summary[service]['open_events'] += 1
            elif status == 'closed':
                service_summary[service]['closed_events'] += 1
            elif status == 'upcoming':
                service_summary[service]['upcoming_events'] += 1
            
            # Update region summary
            if region not in region_summary:
                region_summary[region] = {
                    'total_events': 0,
                    'open_events': 0,
                    'closed_events': 0,
                    'upcoming_events': 0
                }
            
            region_summary[region]['total_events'] += 1
            if status == 'open':
                region_summary[region]['open_events'] += 1
            elif status == 'closed':
                region_summary[region]['closed_events'] += 1
            elif status == 'upcoming':
                region_summary[region]['upcoming_events'] += 1
            
            # Update category summary
            if category not in category_summary:
                category_summary[category] = {
                    'total_events': 0,
                    'open_events': 0,
                    'closed_events': 0,
                    'upcoming_events': 0
                }
            
            category_summary[category]['total_events'] += 1
            if status == 'open':
                category_summary[category]['open_events'] += 1
            elif status == 'closed':
                category_summary[category]['closed_events'] += 1
            elif status == 'upcoming':
                category_summary[category]['upcoming_events'] += 1
        
        return {
            "status": "success",
            "service": "AWS Health Dashboard",
            "event_count": len(events),
            "events": events,
            "active_event_count": len(active_events),
            "service_summary": service_summary,
            "region_summary": region_summary,
            "category_summary": category_summary,
            "active_events": active_events,
            "timestamp": self._format_timestamp(self.current_time)
        }
    
    def generate_trusted_advisor_issues(self, count: int = 15) -> Dict[str, Any]:
        """
        Generate synthetic AWS Trusted Advisor issues.
        
        Args:
            count: Number of Trusted Advisor issues to generate
            
        Returns:
            Dictionary containing AWS Trusted Advisor issues
        """
        issues = []
        
        # Generate random Trusted Advisor issues
        for _ in range(count):
            # Select a random category
            category = random.choice(self.trusted_advisor_categories)
            
            # Select a random check from that category
            check_name = random.choice(self.trusted_advisor_checks[category])
            
            # Generate a random check ID
            check_id = f"check-{uuid.uuid4().hex[:8]}"
            
            # Determine the status
            status_options = ["error", "warning", "ok"]
            status_weights = [0.3, 0.5, 0.2]  # More warnings than errors or ok
            status = random.choices(status_options, weights=status_weights, k=1)[0]
            
            # Generate a random number of flagged resources
            resources_flagged = random.randint(1, 20) if status in ["error", "warning"] else 0
            
            # Create the Trusted Advisor issue
            issue = {
                'check_id': check_id,
                'name': check_name,
                'description': f"Checks for {check_name.lower()} that could result in {category.replace('_', ' ')} issues.",
                'category': category,
                'status': status,
                'resources_flagged': resources_flagged,
                'timestamp': self._format_timestamp(self._random_timestamp(hours_ago=72))
            }
            
            issues.append(issue)
        
        # Create patterns of related issues
        # For example, security issues related to the same service
        security_issues = [issue for issue in issues if issue['category'] == 'security']
        if len(security_issues) >= 2:
            # Create a pattern of security issues for S3
            for i in range(min(2, len(security_issues))):
                security_issues[i]['name'] = "Amazon S3 Bucket Permissions"
                security_issues[i]['description'] = "Checks that your Amazon S3 buckets do not allow public access."
                security_issues[i]['status'] = "error" if i == 0 else "warning"
                security_issues[i]['resources_flagged'] = random.randint(3, 8) if i == 0 else random.randint(1, 5)
        
        # Create a pattern of cost optimization issues
        cost_issues = [issue for issue in issues if issue['category'] == 'cost_optimizing']
        if len(cost_issues) >= 3:
            # Create a pattern of cost issues for EC2, EBS, and RDS
            cost_checks = [
                {"name": "Low Utilization Amazon EC2 Instances", "desc": "Checks for EC2 instances that have been running for a long time with low utilization."},
                {"name": "Underutilized Amazon EBS Volumes", "desc": "Checks for EBS volumes with low IOPS utilization."},
                {"name": "Amazon RDS Idle DB Instances", "desc": "Checks for RDS instances with low connection counts."}
            ]
            
            for i in range(min(3, len(cost_issues))):
                cost_issues[i]['name'] = cost_checks[i]["name"]
                cost_issues[i]['description'] = cost_checks[i]["desc"]
                cost_issues[i]['status'] = "warning"
                cost_issues[i]['resources_flagged'] = random.randint(5, 15)
        
        # Sort issues by status (error first) and then by number of flagged resources
        issues.sort(key=lambda x: (0 if x['status'] == 'error' else 1 if x['status'] == 'warning' else 2, -x['resources_flagged']))
        
        return {
            "status": "success",
            "service": "AWS Trusted Advisor",
            "issue_count": len(issues),
            "issues": issues,
            "timestamp": self._format_timestamp(self.current_time)
        }
    
    def generate_correlated_incident_data(self) -> Dict[str, Any]:
        """
        Generate a set of correlated events across different AWS services that represent a realistic incident.
        
        Returns:
            Dictionary containing correlated events from different AWS monitoring services
        """
        # Create a scenario: EC2 instance type quota exceeded, leading to launch failures,
        # which causes application errors and increased API throttling
        
        # 1. Generate CloudTrail events with throttling and quota exceeded errors
        cloudtrail_data = self.generate_cloudtrail_events(count=200, error_percentage=0.3, throttle_percentage=0.15)
        
        # Modify some events to create a specific pattern
        quota_exceeded_time = self._random_timestamp(hours_ago=6)
        
        # Add quota exceeded errors
        for i in range(min(10, len(cloudtrail_data["error_events"]))):
            event_time = quota_exceeded_time + datetime.timedelta(minutes=i*2)
            cloudtrail_data["error_events"][i]['event_source'] = "ec2.amazonaws.com"
            cloudtrail_data["error_events"][i]['event_name'] = "RunInstances"
            cloudtrail_data["error_events"][i]['error_code'] = "LimitExceededException"
            cloudtrail_data["error_events"][i]['error_message'] = "You have requested more instances (10) than your current instance limit of 5 allows for the specified instance type. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment to this limit."
            cloudtrail_data["error_events"][i]['event_time'] = self._format_timestamp(event_time)
        
        # Add throttling errors after quota exceeded
        for i in range(min(15, len(cloudtrail_data["throttle_events"]))):
            event_time = quota_exceeded_time + datetime.timedelta(minutes=i*5 + 30)
            cloudtrail_data["throttle_events"][i]['event_source'] = "ec2.amazonaws.com"
            cloudtrail_data["throttle_events"][i]['event_name'] = "DescribeInstances"
            cloudtrail_data["throttle_events"][i]['error_code'] = "ThrottlingException"
            cloudtrail_data["throttle_events"][i]['error_message'] = "Rate exceeded for DescribeInstances"
            cloudtrail_data["throttle_events"][i]['event_time'] = self._format_timestamp(event_time)
        
        # 2. Generate VPC Flow Logs with connection failures
        vpc_flow_data = self.generate_vpc_flow_logs(count=500, rejected_percentage=0.2)
        
        # 3. Generate Health Dashboard events
        health_data = self.generate_health_dashboard_events(count=8)
        
        # Add a specific EC2 service quota event
        service_quota_event_time = quota_exceeded_time - datetime.timedelta(minutes=30)
        health_data["events"][0]['service'] = "ec2"
        health_data["events"][0]['event_type_code'] = "AWS_EC2_INSTANCE_LAUNCH_FAILURE"
        health_data["events"][0]['region'] = self.region
        health_data["events"][0]['start_time'] = self._format_timestamp(service_quota_event_time)
        health_data["events"][0]['status_code'] = "open"
        health_data["events"][0]['event_description'] = f"We are investigating an issue impacting instance launches in the {self.region} region. Existing instances are not impacted."
        
        # Update the service summary
        if "ec2" not in health_data["service_summary"]:
            health_data["service_summary"]["ec2"] = {
                'total_events': 0,
                'open_events': 0,
                'closed_events': 0,
                'upcoming_events': 0
            }
        health_data["service_summary"]["ec2"]['total_events'] += 1
        health_data["service_summary"]["ec2"]['open_events'] += 1
        
        # 4. Generate Trusted Advisor issues
        trusted_advisor_data = self.generate_trusted_advisor_issues(count=12)
        
        # Add a specific service limits issue
        for i in range(min(2, len(trusted_advisor_data["issues"]))):
            trusted_advisor_data["issues"][i]['category'] = "service_limits"
            trusted_advisor_data["issues"][i]['name'] = "EC2 On-Demand Instances"
            trusted_advisor_data["issues"][i]['description'] = "Checks for usage that is more than 80% of the EC2 service limit for on-demand instances."
            trusted_advisor_data["issues"][i]['status'] = "error" if i == 0 else "warning"
            trusted_advisor_data["issues"][i]['resources_flagged'] = 5 if i == 0 else 3
        
        # Combine all data
        return {
            "cloudtrail_errors": cloudtrail_data,
            "vpc_flow_logs": vpc_flow_data,
            "health_events": health_data,
            "trusted_advisor_issues": trusted_advisor_data,
            "incident_timeline": {
                "quota_exceeded_time": self._format_timestamp(quota_exceeded_time),
                "service_quota_event_time": self._format_timestamp(service_quota_event_time)
            },
            "timestamp": self._format_timestamp(self.current_time)
        }
    
    def generate_incident_description(self) -> str:
        """
        Generate a description of the incident for root cause analysis.
        
        Returns:
            Incident description string
        """
        return """
        Incident: Application Deployment Failure and Increased Error Rates
        
        On April 5, 2025, our automated deployment system attempted to scale up our application in response to increased traffic. 
        The deployment failed with several errors, and users reported increased latency and error rates.
        
        Symptoms:
        - Automated deployment failed to launch new EC2 instances
        - Application error rates increased from 0.1% to 5%
        - API latency increased by 300%
        - Several API calls resulted in throttling errors
        - Monitoring dashboards showed increased connection failures
        
        Initial investigation showed that the deployment system was unable to launch new EC2 instances, 
        but the root cause is unclear. We need to analyze logs, metrics, and AWS service health to determine 
        the root cause and prevent similar incidents in the future.
        """


def main():
    """Generate test data and save it to files."""
    generator = TestDataGenerator(seed=42)
    
    # Generate correlated incident data
    incident_data = generator.generate_correlated_incident_data()
    
    # Save the data to files
    with open('test_data_cloudtrail.json', 'w') as f:
        json.dump(incident_data["cloudtrail_errors"], f, indent=2)
    
    with open('test_data_vpc_flow_logs.json', 'w') as f:
        json.dump(incident_data["vpc_flow_logs"], f, indent=2)
    
    with open('test_data_health_events.json', 'w') as f:
        json.dump(incident_data["health_events"], f, indent=2)
    
    with open('test_data_trusted_advisor.json', 'w') as f:
        json.dump(incident_data["trusted_advisor_issues"], f, indent=2)
    
    with open('test_data_incident.json', 'w') as f:
        json.dump(incident_data, f, indent=2)
    
    print("Test data generated and saved to files.")
    
    # Generate incident description
    incident_description = generator.generate_incident_description()
    
    with open('test_data_incident_description.txt', 'w') as f:
        f.write(incident_description)
    
    print("Incident description saved to file.")


if __name__ == "__main__":
    main()
