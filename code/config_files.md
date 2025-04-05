# Configuration Files for SRE Copilot

This file contains sample configuration files for the SRE copilot system.

## Sample Config File (config.json)

```json
{
  "aws_region": "us-east-1",
  "create_agents": false,
  "supervisor_agent": {
    "id": "existing-supervisor-agent-id",
    "name": "SRE-Copilot-Supervisor",
    "description": "Supervisor agent for SRE root cause analysis",
    "foundation_model_id": "amazon.nova-pro-v1:0"
  },
  "log_analysis_agent": {
    "id": "existing-log-analysis-agent-id",
    "name": "SRE-Copilot-Log-Analyzer",
    "description": "Specialized agent for log analysis",
    "foundation_model_id": "anthropic.claude-3-haiku-20240307-v1:0"
  },
  "metrics_analysis_agent": {
    "id": "existing-metrics-analysis-agent-id",
    "name": "SRE-Copilot-Metrics-Analyzer",
    "description": "Specialized agent for metrics analysis",
    "foundation_model_id": "amazon.titan-text-express-v1"
  },
  "dashboard_analysis_agent": {
    "id": "existing-dashboard-analysis-agent-id",
    "name": "SRE-Copilot-Dashboard-Analyzer",
    "description": "Specialized agent for dashboard analysis",
    "foundation_model_id": "amazon.nova-lite-v1:0"
  },
  "knowledge_base_agent": {
    "id": "existing-knowledge-base-agent-id",
    "name": "SRE-Copilot-Knowledge-Base",
    "description": "Specialized agent for knowledge base management",
    "foundation_model_id": "amazon.titan-embed-text-v1"
  },
  "knowledge_base": {
    "id": "existing-knowledge-base-id",
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

## Sample Incident File (incident.json)

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

## Sample Requirements File (requirements.txt)

```
boto3>=1.28.0
pandas>=2.0.0
numpy>=1.24.0
pillow>=10.0.0
matplotlib>=3.7.0
requests>=2.31.0
```

## Sample Setup Script (setup.sh)

```bash
#!/bin/bash

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up AWS credentials (if not already configured)
if [ ! -f ~/.aws/credentials ]; then
    mkdir -p ~/.aws
    echo "[default]" > ~/.aws/credentials
    echo "aws_access_key_id = YOUR_ACCESS_KEY" >> ~/.aws/credentials
    echo "aws_secret_access_key = YOUR_SECRET_KEY" >> ~/.aws/credentials
    echo "region = us-east-1" >> ~/.aws/config
    echo "Please update ~/.aws/credentials with your actual AWS credentials"
fi

# Create necessary directories
mkdir -p logs
mkdir -p reports

echo "Setup complete. Please update AWS credentials if needed."
```

## Sample Run Script (run.sh)

```bash
#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Default values
CONFIG_FILE="config.json"
INCIDENT_FILE="incident.json"
OUTPUT_FILE="reports/rca_report_$(date +%Y%m%d_%H%M%S).json"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --config)
        CONFIG_FILE="$2"
        shift
        shift
        ;;
        --incident)
        INCIDENT_FILE="$2"
        shift
        shift
        ;;
        --output)
        OUTPUT_FILE="$2"
        shift
        shift
        ;;
        *)
        echo "Unknown option: $1"
        exit 1
        ;;
    esac
done

# Run the SRE copilot
echo "Starting SRE copilot with:"
echo "  Config: $CONFIG_FILE"
echo "  Incident: $INCIDENT_FILE"
echo "  Output: $OUTPUT_FILE"

python main.py --config "$CONFIG_FILE" --incident "$INCIDENT_FILE" --output "$OUTPUT_FILE"

echo "Analysis complete. Report saved to $OUTPUT_FILE"
```
