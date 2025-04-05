# Deployment Guide: SRE Copilot with AWS Bedrock

This guide provides detailed instructions for deploying the SRE Copilot system in your AWS environment.

## Prerequisites

Before deploying the SRE Copilot, ensure you have the following:

- AWS Account with access to AWS Bedrock
- IAM permissions to create and manage the following resources:
  - AWS Bedrock agents and knowledge bases
  - CloudWatch logs, metrics, and dashboards
  - IAM roles and policies
  - OpenSearch Serverless collections (for knowledge base)
- Python 3.8 or higher
- AWS CLI installed and configured
- Git for cloning the repository

## Architecture Overview

The SRE Copilot consists of the following components:

1. **AWS Bedrock Agents**:
   - Supervisor Agent: Coordinates analysis and synthesizes results
   - Log Analysis Agent: Analyzes log data
   - Metrics Analysis Agent: Analyzes metrics data
   - Dashboard Analysis Agent: Analyzes dashboard visualizations
   - Knowledge Base Agent: Provides historical context

2. **AWS Bedrock Knowledge Base**:
   - Stores historical incident data
   - Provides context for current incidents

3. **Data Sources**:
   - CloudWatch Logs
   - CloudWatch Metrics
   - CloudWatch Dashboards

4. **SRE Copilot Application**:
   - Python application that orchestrates the analysis
   - Integrates with AWS services
   - Generates comprehensive reports

## Deployment Steps

### Step 1: Set Up AWS Resources

#### Create IAM Role for SRE Copilot

1. Navigate to the IAM console
2. Create a new role with the following permissions:
   - `AmazonBedrockFullAccess`
   - `CloudWatchFullAccess`
   - `AmazonOpenSearchServerlessFullAccess`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:*",
        "cloudwatch:*",
        "logs:*",
        "aoss:*"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Create OpenSearch Serverless Collection for Knowledge Base

1. Navigate to the OpenSearch Serverless console
2. Create a new collection:
   - Name: `sre-incidents`
   - Data access policy: Create a new policy with the following settings:
     - Name: `sre-incidents-access`
     - Rules: Allow the SRE Copilot IAM role full access

```json
{
  "Rules": [
    {
      "ResourceType": "collection",
      "Resource": [
        "collection/sre-incidents"
      ],
      "Permission": [
        "aoss:CreateCollectionItems",
        "aoss:DeleteCollectionItems",
        "aoss:UpdateCollectionItems",
        "aoss:DescribeCollectionItems"
      ]
    },
    {
      "ResourceType": "index",
      "Resource": [
        "index/sre-incidents/*"
      ],
      "Permission": [
        "aoss:ReadDocument",
        "aoss:WriteDocument"
      ]
    }
  ],
  "Principal": [
    "arn:aws:iam::123456789012:role/SRECopilotRole"
  ]
}
```

3. Create a vector index:
   - Name: `sre-incidents-index`
   - Mapping:

```json
{
  "mappings": {
    "properties": {
      "incident_id": {
        "type": "keyword"
      },
      "description": {
        "type": "text"
      },
      "root_cause": {
        "type": "text"
      },
      "resolution": {
        "type": "text"
      },
      "services_affected": {
        "type": "keyword"
      },
      "embedding": {
        "type": "knn_vector",
        "dimension": 1536
      }
    }
  }
}
```

### Step 2: Set Up AWS Bedrock

#### Enable Foundation Models

1. Navigate to the AWS Bedrock console
2. Go to Model access
3. Request access to the following models:
   - Amazon Nova Pro
   - Amazon Nova Lite
   - Amazon Titan Text
   - Anthropic Claude 3 Haiku
   - Amazon Titan Embeddings

#### Create Knowledge Base

1. Navigate to the AWS Bedrock console
2. Go to Knowledge bases
3. Create a new knowledge base:
   - Name: `SRE-Incident-Knowledge-Base`
   - Description: `Knowledge base for storing historical incident data`
   - Data source: OpenSearch Serverless
   - Collection: `sre-incidents`
   - Vector index: `sre-incidents-index`
   - Embedding model: Amazon Titan Embeddings
   - IAM role: Create or use existing role with appropriate permissions

#### Create Bedrock Agents

1. Navigate to the AWS Bedrock console
2. Go to Agents
3. Create the following agents:

**Supervisor Agent**:
- Name: `SRE-Copilot-Supervisor`
- Description: `Supervisor agent for SRE root cause analysis`
- Foundation model: Amazon Nova Pro
- Instructions:
```
You are a Supervisor Agent for SRE root cause analysis. Your role is to coordinate specialized agents to analyze logs, metrics, and dashboards to determine the root cause of incidents.
```

**Log Analysis Agent**:
- Name: `SRE-Copilot-Log-Analyzer`
- Description: `Specialized agent for log analysis`
- Foundation model: Anthropic Claude 3 Haiku
- Instructions:
```
You are a Log Analysis Agent. Your role is to process and analyze log data to identify patterns, anomalies, and error conditions that may indicate the root cause of incidents.
```

**Metrics Analysis Agent**:
- Name: `SRE-Copilot-Metrics-Analyzer`
- Description: `Specialized agent for metrics analysis`
- Foundation model: Amazon Titan Text
- Instructions:
```
You are a Metrics Analysis Agent. Your role is to analyze time-series metrics data to identify anomalies, correlations, and performance issues that may indicate the root cause of incidents.
```

**Dashboard Analysis Agent**:
- Name: `SRE-Copilot-Dashboard-Analyzer`
- Description: `Specialized agent for dashboard analysis`
- Foundation model: Amazon Nova Lite
- Instructions:
```
You are a Dashboard Interpretation Agent. Your role is to analyze dashboard visualizations to extract insights, identify visual patterns, and correlate visual information with other data sources.
```

**Knowledge Base Agent**:
- Name: `SRE-Copilot-Knowledge-Base`
- Description: `Specialized agent for knowledge base management`
- Foundation model: Amazon Titan Text
- Instructions:
```
You are a Knowledge Base Agent. Your role is to maintain and query historical incident data to provide context, identify similar past incidents, and suggest potential solutions based on previous experiences.
```

#### Set Up Multi-Agent Collaboration

1. Navigate to the AWS Bedrock console
2. Go to Agents
3. Select the Supervisor Agent
4. Set up collaboration:
   - Add all specialized agents as collaborators
   - Configure appropriate permissions

### Step 3: Deploy the SRE Copilot Application

#### Clone the Repository

```bash
git clone https://github.com/your-organization/sre-copilot.git
cd sre-copilot
```

#### Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### Configure the Application

1. Create a configuration file (`config.json`) with the agent IDs and knowledge base ID:

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

2. Create necessary directories:

```bash
mkdir -p screenshots videos reports
```

#### Test the Deployment

Run a test analysis to verify the deployment:

```bash
python main.py --config config.json --incident sample_incident.json --output reports/test_report.json
```

### Step 4: Set Up CI/CD Pipeline (Optional)

For automated deployment, you can set up a CI/CD pipeline using AWS CodePipeline:

1. Create a CodeCommit repository for the SRE Copilot code
2. Set up a CodeBuild project with the following buildspec.yml:

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.9
    commands:
      - echo Installing dependencies...
      - pip install -r requirements.txt
  
  build:
    commands:
      - echo Running tests...
      - python -m unittest discover -s tests
  
  post_build:
    commands:
      - echo Build completed successfully

artifacts:
  files:
    - '**/*'
  base-directory: '.'
```

3. Set up a CodeDeploy application and deployment group
4. Configure CodePipeline to connect these components

## Production Deployment Considerations

### Scaling

For production deployments with multiple concurrent analyses:

1. **Containerization**:
   - Containerize the application using Docker
   - Create a Dockerfile:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py", "--config", "config.json", "--incident", "incident.json", "--output", "reports/report.json"]
```

2. **AWS ECS/Fargate**:
   - Deploy as ECS tasks for scalable execution
   - Configure task definitions with appropriate memory and CPU

3. **API Gateway and Lambda**:
   - Create an API for triggering analyses
   - Use Lambda functions to start ECS tasks

### High Availability

For high availability:

1. **Multi-Region Deployment**:
   - Deploy in multiple AWS regions
   - Use Route 53 for DNS failover

2. **Redundant Data Sources**:
   - Configure backup data sources
   - Implement fallback mechanisms

### Security

For enhanced security:

1. **VPC Deployment**:
   - Deploy within a VPC
   - Use VPC endpoints for AWS services

2. **Encryption**:
   - Enable encryption at rest for all data
   - Use KMS for key management

3. **Secrets Management**:
   - Use AWS Secrets Manager for credentials
   - Rotate credentials regularly

### Monitoring

For operational monitoring:

1. **CloudWatch Alarms**:
   - Set up alarms for application metrics
   - Monitor AWS Bedrock usage and quotas

2. **Logging**:
   - Configure comprehensive logging
   - Use CloudWatch Logs Insights for analysis

3. **Dashboards**:
   - Create operational dashboards
   - Monitor system health and performance

## Cost Optimization

To optimize costs:

1. **AWS Bedrock Usage**:
   - Monitor token usage
   - Use smaller models for less complex analyses

2. **Resource Sizing**:
   - Right-size ECS tasks or EC2 instances
   - Use Spot instances where appropriate

3. **Data Retention**:
   - Implement lifecycle policies for logs and reports
   - Archive older data to S3 Glacier

## Troubleshooting

### Common Deployment Issues

1. **AWS Bedrock Access**:
   - Ensure models are enabled in your account
   - Check IAM permissions

2. **Knowledge Base Integration**:
   - Verify OpenSearch Serverless configuration
   - Check vector index mapping

3. **Agent Collaboration**:
   - Verify multi-agent collaboration setup
   - Check agent aliases and versions

### Logging and Debugging

Enable detailed logging for troubleshooting:

```bash
export LOG_LEVEL=DEBUG
python main.py --config config.json --incident incident.json --output reports/rca_report.json
```

## Maintenance

### Regular Updates

1. **Foundation Models**:
   - Monitor for new model versions
   - Test and update as needed

2. **Dependencies**:
   - Regularly update Python dependencies
   - Check for security vulnerabilities

### Backup and Recovery

1. **Configuration Backup**:
   - Back up agent configurations
   - Store knowledge base data

2. **Disaster Recovery**:
   - Document recovery procedures
   - Test recovery processes regularly

## Conclusion

This deployment guide provides a comprehensive approach to deploying the SRE Copilot with AWS Bedrock in your environment. By following these steps, you can set up a powerful root cause analysis system that leverages advanced AI capabilities to improve incident response and resolution.

For additional support, refer to the AWS Bedrock documentation and the SRE Copilot user guide.
