#!/usr/bin/env python3
"""
SRE Copilot Demonstration Script

This script demonstrates the SRE copilot's root cause analysis capabilities
by running a complete analysis on generated test data.

Usage:
    python3 demo.py
"""

import os
import sys
import json
import logging
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from monitoring_agents.root_cause_analysis_system import RootCauseAnalysisSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sre_copilot_demo.log')
    ]
)
logger = logging.getLogger("SRE-Copilot-Demo")

def main():
    """Run the SRE copilot demonstration."""
    logger.info("Starting SRE Copilot demonstration")
    
    # Create results directory
    os.makedirs('results', exist_ok=True)
    
    try:
        # Initialize the root cause analysis system
        logger.info("Initializing root cause analysis system")
        rca_system = RootCauseAnalysisSystem()
        
        # Run the demonstration
        logger.info("Running root cause analysis demonstration")
        results = rca_system.run_demonstration()
        
        # Print a summary
        print("\n" + "="*80)
        print("SRE COPILOT DEMONSTRATION RESULTS")
        print("="*80)
        print(f"Demonstration ID: {results['summary']['demonstration_id']}")
        print(f"Timestamp: {results['summary']['timestamp']}")
        print(f"Incident: {results['summary']['incident_title']}")
        print(f"Root Cause: {results['summary']['root_cause_summary']}")
        print("\nComponents Demonstrated:")
        for component in results['summary']['components_demonstrated']:
            print(f"  - {component}")
        print("\nFiles Generated:")
        for file in results['summary']['files_generated']:
            print(f"  - {file}")
        print("\nSee the 'results' directory for all generated files.")
        print("="*80)
        
        # Create an HTML report
        create_html_report(results)
        
        logger.info("Demonstration completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Demonstration failed: {str(e)}", exc_info=True)
        print(f"ERROR: Demonstration failed: {str(e)}")
        return 1

def create_html_report(results):
    """Create an HTML report of the demonstration results."""
    logger.info("Creating HTML report")
    
    # Load the analysis results
    try:
        with open('results/root_cause_analysis.json', 'r') as f:
            rca_results = json.load(f)
        
        with open('results/incident_report.json', 'r') as f:
            report_results = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load analysis results: {str(e)}")
        return
    
    # Extract the relevant information
    incident_report = report_results.get('report', {})
    root_cause = rca_results.get('analysis', {}).get('root_cause', {})
    timeline = rca_results.get('analysis', {}).get('timeline', [])
    recommendations = rca_results.get('analysis', {}).get('recommendations', [])
    
    # Create the HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SRE Copilot - Root Cause Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4 {{
            color: #0066cc;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 5px solid #0066cc;
        }}
        .section {{
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .timeline-item {{
            margin-bottom: 15px;
            padding-left: 20px;
            border-left: 3px solid #0066cc;
        }}
        .recommendation {{
            background-color: #f0f7ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        .severity-high {{
            color: #d9534f;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f0ad4e;
            font-weight: bold;
        }}
        .severity-low {{
            color: #5cb85c;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #777;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{incident_report.get('title', 'Root Cause Analysis Report')}</h1>
        <p><strong>Incident ID:</strong> {incident_report.get('incident_id', 'Unknown')}</p>
        <p><strong>Date:</strong> {incident_report.get('date', 'Unknown')}</p>
        <p><strong>Status:</strong> {incident_report.get('status', 'Unknown')}</p>
        <p><strong>Severity:</strong> <span class="severity-{incident_report.get('severity', 'medium').lower()}">{incident_report.get('severity', 'Medium')}</span></p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{incident_report.get('executive_summary', 'No executive summary available.')}</p>
    </div>
    
    <div class="section">
        <h2>Incident Details</h2>
        <p><strong>Description:</strong> {incident_report.get('incident_details', {}).get('description', 'No description available.')}</p>
        <p><strong>Detection:</strong> {incident_report.get('incident_details', {}).get('detection', 'Unknown')}</p>
        <p><strong>Duration:</strong> {incident_report.get('incident_details', {}).get('duration', 'Unknown')}</p>
        
        <h3>Affected Services</h3>
        <ul>
"""
    
    # Add affected services
    affected_services = incident_report.get('incident_details', {}).get('affected_services', [])
    if affected_services:
        for service in affected_services:
            html_content += f"            <li>{service}</li>\n"
    else:
        html_content += "            <li>No affected services reported</li>\n"
    
    html_content += """        </ul>
        
        <h3>Affected Regions</h3>
        <ul>
"""
    
    # Add affected regions
    affected_regions = incident_report.get('incident_details', {}).get('affected_regions', [])
    if affected_regions:
        for region in affected_regions:
            html_content += f"            <li>{region}</li>\n"
    else:
        html_content += "            <li>No affected regions reported</li>\n"
    
    html_content += """        </ul>
    </div>
    
    <div class="section">
        <h2>Root Cause</h2>
        <p><strong>Summary:</strong> {}</p>
        <p><strong>Technical Details:</strong> {}</p>
        
        <h3>Contributing Factors</h3>
        <ul>
""".format(
        root_cause.get('primary_cause', 'Unknown'),
        root_cause.get('technical_details', 'No technical details available.')
    )
    
    # Add contributing factors
    contributing_factors = rca_results.get('analysis', {}).get('contributing_factors', [])
    if contributing_factors:
        for factor in contributing_factors:
            if isinstance(factor, dict):
                html_content += f"            <li><strong>{factor.get('factor', 'Unknown')}:</strong> {factor.get('description', '')}</li>\n"
            else:
                html_content += f"            <li>{factor}</li>\n"
    else:
        html_content += "            <li>No contributing factors reported</li>\n"
    
    html_content += """        </ul>
    </div>
    
    <div class="section">
        <h2>Timeline</h2>
"""
    
    # Add timeline
    if timeline:
        for event in timeline:
            if isinstance(event, dict):
                html_content += f"""        <div class="timeline-item">
            <p><strong>{event.get('timestamp', 'Unknown time')}:</strong> {event.get('event', 'Unknown event')}</p>
            <p><em>Significance: {event.get('significance', 'Unknown')}</em></p>
        </div>
"""
            else:
                html_content += f"""        <div class="timeline-item">
            <p>{event}</p>
        </div>
"""
    else:
        html_content += "        <p>No timeline events available</p>\n"
    
    html_content += """    </div>
    
    <div class="section">
        <h2>Impact</h2>
"""
    
    # Add impact information
    impact = incident_report.get('impact', {})
    if impact:
        html_content += f"""        <p><strong>Service Impact:</strong> {impact.get('service_impact', 'Unknown')}</p>
        <p><strong>Customer Impact:</strong> {impact.get('customer_impact', 'Unknown')}</p>
        <p><strong>Business Impact:</strong> {impact.get('business_impact', 'Unknown')}</p>
        
        <h3>Impact Metrics</h3>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Downtime</td>
                <td>{impact.get('metrics', {}).get('downtime', 'Unknown')}</td>
            </tr>
            <tr>
                <td>Error Rate</td>
                <td>{impact.get('metrics', {}).get('error_rate', 'Unknown')}</td>
            </tr>
            <tr>
                <td>Affected Customers</td>
                <td>{impact.get('metrics', {}).get('affected_customers', 'Unknown')}</td>
            </tr>
        </table>
"""
    else:
        html_content += "        <p>No impact information available</p>\n"
    
    html_content += """    </div>
    
    <div class="section">
        <h2>Resolution</h2>
"""
    
    # Add resolution information
    resolution = incident_report.get('resolution', {})
    if resolution:
        html_content += f"""        <p><strong>Resolution Time:</strong> {resolution.get('resolution_time', 'Unknown')}</p>
        <p><strong>Verification:</strong> {resolution.get('verification', 'Unknown')}</p>
        
        <h3>Actions Taken</h3>
        <ul>
"""
        
        actions_taken = resolution.get('actions_taken', [])
        if actions_taken:
            for action in actions_taken:
                html_content += f"            <li>{action}</li>\n"
        else:
            html_content += "            <li>No actions reported</li>\n"
        
        html_content += "        </ul>\n"
    else:
        html_content += "        <p>No resolution information available</p>\n"
    
    html_content += """    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
"""
    
    # Add recommendations
    if recommendations:
        for i, rec in enumerate(recommendations):
            if isinstance(rec, dict):
                html_content += f"""        <div class="recommendation">
            <h3>Recommendation {i+1}: {rec.get('recommendation', 'Unnamed')}</h3>
            <p><strong>Category:</strong> {rec.get('category', 'Unknown')}</p>
            <p><strong>Priority:</strong> {rec.get('priority', 'Unknown')}</p>
            <p><strong>Implementation:</strong> {rec.get('implementation', 'No implementation details available.')}</p>
        </div>
"""
            else:
                html_content += f"""        <div class="recommendation">
            <h3>Recommendation {i+1}</h3>
            <p>{rec}</p>
        </div>
"""
    else:
        html_content += "        <p>No recommendations available</p>\n"
    
    html_content += """    </div>
    
    <div class="section">
        <h2>Action Items</h2>
        <table>
            <tr>
                <th>Item</th>
                <th>Owner</th>
                <th>Deadline</th>
                <th>Status</th>
                <th>Priority</th>
            </tr>
"""
    
    # Add action items
    action_items = incident_report.get('action_items', [])
    if action_items:
        for item in action_items:
            if isinstance(item, dict):
                html_content += f"""            <tr>
                <td>{item.get('item', 'Unknown')}</td>
                <td>{item.get('owner', 'Unassigned')}</td>
                <td>{item.get('deadline', 'No deadline')}</td>
                <td>{item.get('status', 'Not started')}</td>
                <td class="severity-{item.get('priority', 'medium').lower()}">{item.get('priority', 'Medium')}</td>
            </tr>
"""
            else:
                html_content += f"""            <tr>
                <td colspan="5">{item}</td>
            </tr>
"""
    else:
        html_content += """            <tr>
                <td colspan="5">No action items available</td>
            </tr>
"""
    
    html_content += """        </table>
    </div>
    
    <div class="section">
        <h2>Lessons Learned</h2>
        <ul>
"""
    
    # Add lessons learned
    lessons_learned = incident_report.get('lessons_learned', [])
    if lessons_learned:
        for lesson in lessons_learned:
            html_content += f"            <li>{lesson}</li>\n"
    else:
        html_content += "            <li>No lessons learned reported</li>\n"
    
    html_content += """        </ul>
    </div>
    
    <div class="footer">
        <p>Generated by SRE Copilot with AWS Bedrock on {}</p>
        <p>This report combines analysis from CloudTrail, VPC Flow Logs, AWS Health Dashboard, and Trusted Advisor</p>
    </div>
</body>
</html>
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Write the HTML file
    with open('results/root_cause_analysis_report.html', 'w') as f:
        f.write(html_content)
    
    logger.info("HTML report created: results/root_cause_analysis_report.html")

if __name__ == "__main__":
    sys.exit(main())
