# User Guide: SRE Copilot with AWS Bedrock

## Introduction

The SRE Copilot is an advanced root cause analysis system built on AWS Bedrock that helps Site Reliability Engineers quickly identify the root causes of incidents by analyzing logs, metrics, and dashboards. The system uses a multi-agent architecture with multi-modal capabilities to provide comprehensive insights across different data sources.

This guide will help you set up, configure, and use the SRE Copilot for incident analysis.

## System Requirements

- AWS Account with access to AWS Bedrock
- Python 3.8 or higher
- AWS CLI configured with appropriate permissions
- Required Python packages (see requirements.txt)

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-organization/sre-copilot.git
cd sre-copilot
```

### Step 2: Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure AWS Credentials

Ensure your AWS credentials are configured with access to the following services:
- AWS Bedrock
- CloudWatch Logs
- CloudWatch Metrics
- CloudWatch Dashboards

```bash
aws configure
```

### Step 5: Set Up AWS Bedrock Agents

You can either create the agents manually through the AWS console or use the provided setup script:

```bash
# Edit config.json to set create_agents=true
# Then run the setup script
./setup.sh
```

## Configuration

### Configuration File (config.json)

The main configuration file defines the AWS Bedrock agents and knowledge base settings:

```json
{
  "aws_region": "us-east-1",
  "create_agents": false,
  "supervisor_agent": {
    "id": "your-supervisor-agent-id",
    "name": "SRE-Copilot-Supervisor",
    "description": "Supervisor agent for SRE root cause analysis",
    "foundation_model_id": "amazon.nova-pro-v1:0"
  },
  "log_analysis_agent": {
    "id": "your-log-analysis-agent-id",
    "name": "SRE-Copilot-Log-Analyzer",
    "description": "Specialized agent for log analysis",
    "foundation_model_id": "anthropic.claude-3-haiku-20240307-v1:0"
  },
  "metrics_analysis_agent": {
    "id": "your-metrics-analysis-agent-id",
    "name": "SRE-Copilot-Metrics-Analyzer",
    "description": "Specialized agent for metrics analysis",
    "foundation_model_id": "amazon.titan-text-express-v1"
  },
  "dashboard_analysis_agent": {
    "id": "your-dashboard-analysis-agent-id",
    "name": "SRE-Copilot-Dashboard-Analyzer",
    "description": "Specialized agent for dashboard analysis",
    "foundation_model_id": "amazon.nova-lite-v1:0"
  },
  "knowledge_base_agent": {
    "id": "your-knowledge-base-agent-id",
    "name": "SRE-Copilot-Knowledge-Base",
    "description": "Specialized agent for knowledge base management",
    "foundation_model_id": "amazon.titan-embed-text-v1"
  },
  "knowledge_base": {
    "id": "your-knowledge-base-id",
    "name": "SRE-Incident-Knowledge-Base",
    "description": "Knowledge base for storing historical incident data",
    "data_source_config": {
      "collectionId": "sre-incidents",
      "vectorIndexName": "sre-incidents-index",
      "roleArn": "arn:aws:iam::123456789012:role/SREKnowledgeBaseRole"
    }
  }
}
```

### Incident File (incident.json)

For each incident you want to analyze, create an incident file with the following structure:

```json
{
  "incident_id": "INC-2025-04-05-001",
  "start_time": "2025-04-05T08:30:00Z",
  "end_time": "2025-04-05T09:45:00Z",
  "severity": "high",
  "services_affected": ["payment-service", "checkout-api", "order-processor"],
  "description": "Customers unable to complete checkout process, receiving 500 errors",
  "log_sources": [
    {
      "type": "cloudwatch",
      "name": "payment-service-logs",
      "log_group_name": "/aws/lambda/payment-service",
      "filter_pattern": "ERROR"
    },
    {
      "type": "cloudwatch",
      "name": "checkout-api-logs",
      "log_group_name": "/aws/apigateway/checkout-api",
      "filter_pattern": "ERROR"
    },
    {
      "type": "cloudwatch",
      "name": "order-processor-logs",
      "log_group_name": "/aws/ecs/order-processor",
      "filter_pattern": "ERROR"
    }
  ],
  "metric_sources": [
    {
      "type": "cloudwatch",
      "name": "payment-service-errors",
      "namespace": "AWS/Lambda",
      "metric_name": "Errors",
      "dimensions": [
        {
          "Name": "FunctionName",
          "Value": "payment-service"
        }
      ],
      "period": 60
    },
    {
      "type": "cloudwatch",
      "name": "checkout-api-5xx",
      "namespace": "AWS/ApiGateway",
      "metric_name": "5XXError",
      "dimensions": [
        {
          "Name": "ApiName",
          "Value": "checkout-api"
        }
      ],
      "period": 60
    },
    {
      "type": "cloudwatch",
      "name": "order-processor-cpu",
      "namespace": "AWS/ECS",
      "metric_name": "CPUUtilization",
      "dimensions": [
        {
          "Name": "ServiceName",
          "Value": "order-processor"
        },
        {
          "Name": "ClusterName",
          "Value": "main-cluster"
        }
      ],
      "period": 60
    }
  ],
  "dashboards": [
    {
      "name": "PaymentServiceDashboard",
      "url": "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=PaymentServiceDashboard"
    },
    {
      "name": "CheckoutAPIDashboard",
      "url": "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=CheckoutAPIDashboard"
    }
  ]
}
```

## Usage

### Basic Usage

To analyze an incident:

```bash
python main.py --config config.json --incident incident.json --output reports/rca_report.json
```

### With Video Analysis

To include incident playback video generation and analysis:

```bash
python main_multi_modal.py --config config.json --incident incident.json --output reports/rca_report.json --create-video
```

### Using the Run Script

For convenience, you can use the provided run script:

```bash
./run.sh --config config.json --incident incident.json --output reports/rca_report.json
```

## Understanding the Results

The analysis results are saved as a JSON file with the following structure:

```json
{
  "incident_id": "INC-2025-04-05-001",
  "analysis_time": "2025-04-05T11:30:45.123456",
  "incident_period": {
    "start": "2025-04-05T08:30:00Z",
    "end": "2025-04-05T09:45:00Z"
  },
  "root_cause_analysis": "Detailed root cause analysis text...",
  "log_analysis_summary": {
    "total_logs": 1250,
    "error_logs": 87,
    "warning_logs": 143,
    "anomalies_detected": 3
  },
  "metrics_analysis_summary": {
    "metrics_analyzed": 3,
    "anomalies_detected": 2
  },
  "dashboards_analyzed": {
    "PaymentServiceDashboard": {
      "screenshot_path": "screenshots/PaymentServiceDashboard_INC-2025-04-05-001.png",
      "analysis_methods": ["definition_analysis", "visual_analysis", "enhanced_visual_analysis"]
    },
    "CheckoutAPIDashboard": {
      "screenshot_path": "screenshots/CheckoutAPIDashboard_INC-2025-04-05-001.png",
      "analysis_methods": ["definition_analysis", "visual_analysis", "enhanced_visual_analysis"]
    }
  },
  "video_analysis": {
    "video_path": "videos/INC-2025-04-05-001_playback.mp4",
    "frame_analyses": [...],
    "overall_analysis": "Video analysis text..."
  }
}
```

## Advanced Features

### Knowledge Base Integration

The system can leverage historical incident data stored in a knowledge base to provide context and identify similar past incidents. To populate the knowledge base:

1. Create incident reports in a consistent format
2. Use the AWS Bedrock console to upload documents to the knowledge base
3. Ensure the knowledge base ID is correctly configured in config.json

### Custom Data Sources

While the system is pre-configured for CloudWatch logs and metrics, you can extend it to support additional data sources:

1. Create a new data source adapter class
2. Implement the required fetch and process methods
3. Update the incident file format to include your custom data source

### Multi-Modal Analysis

The system supports multi-modal analysis of dashboards and metrics:

- **Dashboard Visual Analysis**: Captures and analyzes screenshots of dashboards
- **Video Analysis**: Creates and analyzes incident playback videos
- **Cross-Modal Correlation**: Identifies relationships between logs, metrics, and visual data

## Troubleshooting

### Common Issues

1. **AWS Bedrock Access**
   - Ensure your AWS account has access to AWS Bedrock
   - Verify that the foundation models specified in config.json are available in your region

2. **Missing Data**
   - Check that log groups and metrics exist for the specified time period
   - Verify that dashboard URLs are correct and accessible

3. **Permission Errors**
   - Ensure your AWS credentials have the necessary permissions
   - Check IAM roles for CloudWatch and Bedrock access

### Logging

To enable detailed logging:

```bash
export LOG_LEVEL=DEBUG
python main.py --config config.json --incident incident.json --output reports/rca_report.json
```

### Support

For additional support:
- Check the GitHub repository for issues and updates
- Contact your AWS representative for Bedrock-specific questions

## Best Practices

1. **Incident Definition**
   - Include all relevant log sources and metrics
   - Set appropriate time ranges (not too short, not too long)
   - Provide descriptive incident information

2. **Agent Configuration**
   - Choose appropriate foundation models for each agent role
   - Tune agent prompts for your specific environment

3. **Knowledge Base Management**
   - Regularly update the knowledge base with new incidents
   - Maintain consistent formatting of incident reports
   - Include resolution steps in historical data

4. **Performance Optimization**
   - Use filter patterns to reduce log volume
   - Set appropriate metric periods based on incident duration
   - Limit the number of dashboards for visual analysis

## Security Considerations

1. **AWS Credentials**
   - Use IAM roles with least privilege
   - Rotate access keys regularly
   - Consider using AWS Secrets Manager for credential storage

2. **Sensitive Data**
   - Be aware that logs may contain sensitive information
   - Configure log filters to exclude sensitive data
   - Review reports before sharing

3. **Access Control**
   - Restrict access to the SRE Copilot and its reports
   - Implement appropriate authentication for any web interfaces
   - Monitor and audit usage

## Conclusion

The SRE Copilot with AWS Bedrock provides a powerful tool for root cause analysis, leveraging advanced AI capabilities to analyze diverse data sources. By following this guide, you can effectively set up, configure, and use the system to improve incident response and resolution in your organization.

For more detailed information, refer to the architecture documentation and API reference.
