# Multi-Modal Capabilities Implementation

This document outlines the implementation of multi-modal capabilities for the SRE copilot system, enhancing its ability to process and analyze different types of data including text logs, metrics, and dashboard visualizations.

## Dashboard Visual Analysis Component

```python
# dashboard_visual_analysis.py
import boto3
import json
import base64
from PIL import Image
import io
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class DashboardVisualAnalysisComponent:
    def __init__(self, bedrock_runtime, dashboard_analysis_agent_id):
        """Initialize the DashboardVisualAnalysisComponent with Bedrock runtime and agent ID"""
        self.bedrock_runtime = bedrock_runtime
        self.dashboard_analysis_agent_id = dashboard_analysis_agent_id
        
    def capture_dashboard_screenshot(self, dashboard_url, output_path=None):
        """Capture a screenshot of a dashboard using headless Chrome"""
        # Set up headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        
        driver = webdriver.Chrome(options=chrome_options)
        
        try:
            # Navigate to the dashboard URL
            driver.get(dashboard_url)
            
            # Wait for dashboard to load (adjust selector as needed)
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".cwdb-dashboard-container"))
            )
            
            # Take screenshot
            screenshot = driver.get_screenshot_as_png()
            
            # Save screenshot if output path is provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(screenshot)
            
            # Convert to base64 for API calls
            screenshot_base64 = base64.b64encode(screenshot).decode('utf-8')
            
            return screenshot_base64
            
        finally:
            driver.quit()
    
    def analyze_dashboard_image(self, image_base64):
        """Analyze dashboard image using AWS Bedrock multi-modal model"""
        # Use Nova Lite model which supports image inputs
        response = self.bedrock_runtime.invoke_model(
            modelId="amazon.nova-lite-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": image_base64
                                }
                            },
                            {
                                "type": "text",
                                "text": """
                                Analyze this dashboard screenshot to identify potential issues or anomalies.
                                
                                Focus on:
                                1. Any visible error indicators or alerts
                                2. Unusual patterns in charts or graphs
                                3. Metrics that appear to be outside normal ranges
                                4. Correlations between different visualizations
                                5. Any text or annotations that provide context
                                
                                Provide a detailed analysis of what you observe in the dashboard.
                                """
                            }
                        ]
                    }
                ]
            })
        )
        
        response_body = json.loads(response['body'].read())
        analysis = response_body['content'][0]['text']
        
        return {
            'analysis': analysis
        }
    
    def analyze_dashboard_with_context(self, image_base64, metrics_context, logs_context):
        """Analyze dashboard image with additional context from metrics and logs"""
        # Use Nova Pro model which supports image inputs with more context
        response = self.bedrock_runtime.invoke_model(
            modelId="amazon.nova-pro-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": image_base64
                                }
                            },
                            {
                                "type": "text",
                                "text": f"""
                                Analyze this dashboard screenshot to identify potential issues or anomalies.
                                
                                Here is additional context from metrics analysis:
                                {metrics_context}
                                
                                Here is additional context from log analysis:
                                {logs_context}
                                
                                Based on the dashboard visualization and the provided context:
                                1. What visual indicators in the dashboard confirm or contradict the metrics and logs analysis?
                                2. What additional insights can you derive from the dashboard that weren't apparent in the metrics and logs?
                                3. How do the different data sources (dashboard, metrics, logs) correlate to indicate the root cause?
                                4. What specific components or services appear to be problematic based on the dashboard?
                                5. What recommendations would you make based on the combined analysis?
                                
                                Provide a comprehensive analysis that integrates all available information.
                                """
                            }
                        ]
                    }
                ]
            })
        )
        
        response_body = json.loads(response['body'].read())
        analysis = response_body['content'][0]['text']
        
        return {
            'analysis': analysis
        }
```

## Enhanced RCA Coordinator with Multi-Modal Support

```python
# enhanced_rca_coordinator.py
import boto3
import json
import base64
from datetime import datetime, timedelta
from dashboard_visual_analysis import DashboardVisualAnalysisComponent

class EnhancedRCACoordinator:
    def __init__(self, 
                 bedrock_runtime, 
                 supervisor_agent_id,
                 log_analysis_component,
                 metrics_analysis_component,
                 dashboard_analysis_component,
                 dashboard_visual_analysis_component,
                 knowledge_base_id):
        """Initialize the EnhancedRCACoordinator with components and agent IDs"""
        self.bedrock_runtime = bedrock_runtime
        self.supervisor_agent_id = supervisor_agent_id
        self.log_analysis = log_analysis_component
        self.metrics_analysis = metrics_analysis_component
        self.dashboard_analysis = dashboard_analysis_component
        self.dashboard_visual_analysis = dashboard_visual_analysis_component
        self.knowledge_base_id = knowledge_base_id
        
    def analyze_incident(self, incident_info):
        """Coordinate the analysis of an incident with multi-modal capabilities"""
        # Extract incident details
        incident_id = incident_info.get('incident_id', 'unknown')
        start_time = incident_info.get('start_time')
        end_time = incident_info.get('end_time', datetime.now())
        
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time)
        
        # Add buffer before and after incident
        analysis_start_time = start_time - timedelta(minutes=30)
        analysis_end_time = end_time + timedelta(minutes=30)
        
        # Collect log data
        log_sources = incident_info.get('log_sources', [])
        logs = self.log_analysis.fetch_logs_from_multiple_sources(
            log_sources, 
            analysis_start_time, 
            analysis_end_time
        )
        processed_logs = self.log_analysis.preprocess_logs(logs)
        log_anomalies = self.log_analysis.detect_anomalies(processed_logs)
        log_analysis_results = self.log_analysis.analyze_logs(processed_logs, log_anomalies)
        
        # Collect metrics data
        metric_sources = incident_info.get('metric_sources', [])
        metrics = self.metrics_analysis.fetch_metrics_from_multiple_sources(
            metric_sources,
            analysis_start_time,
            analysis_end_time
        )
        metric_anomalies = self.metrics_analysis.detect_anomalies(metrics)
        metrics_analysis_results = self.metrics_analysis.analyze_metrics(metrics, metric_anomalies)
        
        # Analyze dashboards - both definition and visual analysis
        dashboard_results = {}
        for dashboard in incident_info.get('dashboards', []):
            dashboard_name = dashboard.get('name')
            dashboard_url = dashboard.get('url')
            
            # Traditional dashboard definition analysis
            definition_analysis = self.dashboard_analysis.analyze_dashboard(
                dashboard_name=dashboard_name,
                dashboard_url=None  # Don't capture screenshot in traditional analysis
            )
            
            # Visual dashboard analysis
            screenshot_path = f"screenshots/{dashboard_name}_{incident_id}.png"
            try:
                screenshot_base64 = self.dashboard_visual_analysis.capture_dashboard_screenshot(
                    dashboard_url=dashboard_url,
                    output_path=screenshot_path
                )
                
                # Basic visual analysis
                visual_analysis = self.dashboard_visual_analysis.analyze_dashboard_image(
                    image_base64=screenshot_base64
                )
                
                # Enhanced visual analysis with context
                enhanced_visual_analysis = self.dashboard_visual_analysis.analyze_dashboard_with_context(
                    image_base64=screenshot_base64,
                    metrics_context=metrics_analysis_results.get('analysis', ''),
                    logs_context=log_analysis_results.get('analysis', '')
                )
                
                dashboard_results[dashboard_name] = {
                    'definition_analysis': definition_analysis,
                    'visual_analysis': visual_analysis,
                    'enhanced_visual_analysis': enhanced_visual_analysis,
                    'screenshot_path': screenshot_path
                }
            except Exception as e:
                print(f"Error capturing or analyzing dashboard {dashboard_name}: {str(e)}")
                dashboard_results[dashboard_name] = {
                    'definition_analysis': definition_analysis,
                    'error': str(e)
                }
        
        # Synthesize results using supervisor agent with multi-modal context
        synthesis = self.synthesize_multi_modal_analysis(
            incident_info,
            log_analysis_results,
            metrics_analysis_results,
            dashboard_results
        )
        
        # Prepare final report
        report = {
            'incident_id': incident_id,
            'analysis_time': datetime.now().isoformat(),
            'incident_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'root_cause_analysis': synthesis,
            'log_analysis_summary': {
                'total_logs': len(processed_logs),
                'error_logs': len([log for log in processed_logs if log['level'] == 'ERROR']),
                'warning_logs': len([log for log in processed_logs if log['level'] == 'WARN']),
                'anomalies_detected': len(log_anomalies)
            },
            'metrics_analysis_summary': {
                'metrics_analyzed': len(metrics),
                'anomalies_detected': sum(len(anomalies) for anomalies in metric_anomalies.values())
            },
            'dashboards_analyzed': {
                name: {
                    'screenshot_path': analysis.get('screenshot_path'),
                    'analysis_methods': list(filter(lambda k: k != 'screenshot_path' and k != 'error', analysis.keys()))
                }
                for name, analysis in dashboard_results.items()
            }
        }
        
        return report
    
    def synthesize_multi_modal_analysis(self, incident_info, log_analysis, metrics_analysis, dashboard_results):
        """Synthesize analysis results using supervisor agent with multi-modal context"""
        # Prepare context for the agent
        context = {
            'incident_info': {
                'id': incident_info.get('incident_id', 'unknown'),
                'start_time': incident_info.get('start_time').isoformat() if isinstance(incident_info.get('start_time'), datetime) else incident_info.get('start_time'),
                'end_time': incident_info.get('end_time', datetime.now()).isoformat() if isinstance(incident_info.get('end_time'), datetime) else incident_info.get('end_time'),
                'severity': incident_info.get('severity', 'unknown'),
                'services_affected': incident_info.get('services_affected', []),
                'description': incident_info.get('description', '')
            },
            'log_analysis': {
                'summary': log_analysis.get('analysis', '')
            },
            'metrics_analysis': {
                'summary': metrics_analysis.get('analysis', '')
            },
            'dashboard_analysis': {
                name: {
                    'definition_analysis': analysis.get('definition_analysis', {}),
                    'visual_analysis': analysis.get('visual_analysis', {}).get('analysis', ''),
                    'enhanced_visual_analysis': analysis.get('enhanced_visual_analysis', {}).get('analysis', '')
                }
                for name, analysis in dashboard_results.items()
            }
        }
        
        # Invoke Bedrock agent for synthesis
        prompt = f"""
        Synthesize the following multi-modal analysis results to determine the root cause of the incident:
        
        Incident Information:
        {json.dumps(context['incident_info'], indent=2)}
        
        Log Analysis:
        {context['log_analysis']['summary']}
        
        Metrics Analysis:
        {context['metrics_analysis']['summary']}
        
        Dashboard Analysis:
        {json.dumps({name: {
            'visual_analysis': analysis['visual_analysis'],
            'enhanced_visual_analysis': analysis['enhanced_visual_analysis']
        } for name, analysis in context['dashboard_analysis'].items()}, indent=2)}
        
        Based on all this information across multiple data modalities:
        1. What is the most likely root cause of the incident?
        2. What is the sequence of events that led to the incident?
        3. What services or components were affected and how?
        4. What are your recommendations for preventing similar incidents in the future?
        5. What additional information would be helpful for a more complete analysis?
        
        Provide a comprehensive root cause analysis report that integrates insights from logs, metrics, and visual dashboard analysis.
        """
        
        response = self.bedrock_runtime.invoke_agent(
            agentId=self.supervisor_agent_id,
            agentAliasId='TSTALIASID',
            inputText=prompt,
            knowledgeBaseId=self.knowledge_base_id
        )
        
        return response['completion']
```

## Video Analysis Component for Incident Playback

```python
# video_analysis.py
import boto3
import json
import base64
import cv2
import numpy as np
import tempfile
import os
from datetime import datetime

class VideoAnalysisComponent:
    def __init__(self, bedrock_runtime):
        """Initialize the VideoAnalysisComponent with Bedrock runtime"""
        self.bedrock_runtime = bedrock_runtime
        
    def create_incident_playback_video(self, metrics_data, start_time, end_time, output_path):
        """Create a video visualization of metrics during an incident"""
        # Convert metrics data to numpy arrays for visualization
        metric_arrays = {}
        for metric_name, metric_info in metrics_data.items():
            timestamps = [t for t, _ in metric_info['data']]
            values = [v for _, v in metric_info['data']]
            metric_arrays[metric_name] = {
                'timestamps': np.array(timestamps),
                'values': np.array(values)
            }
        
        # Set up video parameters
        fps = 10
        duration = 30  # seconds
        width, height = 1280, 720
        
        # Create video writer
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        video = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        # Calculate total frames
        total_frames = fps * duration
        
        # Generate frames
        for frame_idx in range(total_frames):
            # Create blank frame
            frame = np.ones((height, width, 3), dtype=np.uint8) * 255
            
            # Calculate progress through incident (0 to 1)
            progress = frame_idx / total_frames
            current_time = start_time + (end_time - start_time) * progress
            
            # Draw title and timestamp
            cv2.putText(frame, f"Incident Playback", (50, 50), 
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
            cv2.putText(frame, f"Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}", 
                        (50, 100), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)
            
            # Plot metrics
            y_offset = 150
            for metric_name, metric_data in metric_arrays.items():
                # Find data points up to current time
                mask = metric_data['timestamps'] <= current_time
                if not any(mask):
                    continue
                    
                timestamps = metric_data['timestamps'][mask]
                values = metric_data['values'][mask]
                
                # Normalize to plot area
                plot_height = 100
                plot_width = 800
                x_min, x_max = start_time.timestamp(), end_time.timestamp()
                y_min, y_max = np.min(metric_data['values']), np.max(metric_data['values'])
                y_range = max(y_max - y_min, 1e-10)  # Avoid division by zero
                
                # Draw metric name
                cv2.putText(frame, metric_name, (50, y_offset), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 1)
                
                # Draw axes
                cv2.line(frame, (50, y_offset + 20), (50 + plot_width, y_offset + 20), 
                         (200, 200, 200), 1)  # X-axis
                cv2.line(frame, (50, y_offset + 20 - plot_height), (50, y_offset + 20), 
                         (200, 200, 200), 1)  # Y-axis
                
                # Plot points and lines
                points = []
                for i in range(len(timestamps)):
                    x = 50 + int((timestamps[i].timestamp() - x_min) / (x_max - x_min) * plot_width)
                    y = y_offset + 20 - int((values[i] - y_min) / y_range * plot_height)
                    points.append((x, y))
                
                # Draw lines between points
                for i in range(1, len(points)):
                    cv2.line(frame, points[i-1], points[i], (0, 0, 255), 2)
                
                # Draw points
                for x, y in points:
                    cv2.circle(frame, (x, y), 3, (255, 0, 0), -1)
                
                # Highlight current point
                if points:
                    cv2.circle(frame, points[-1], 5, (0, 255, 0), -1)
                
                # Add current value
                if values.size > 0:
                    cv2.putText(frame, f"Current: {values[-1]:.2f}", (50 + plot_width + 10, y_offset), 
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)
                
                y_offset += plot_height + 50
            
            # Add frame to video
            video.write(frame)
        
        # Release video writer
        video.release()
        
        return output_path
    
    def analyze_incident_video(self, video_path):
        """Analyze incident playback video using AWS Bedrock"""
        # For video analysis, we'll extract key frames and analyze them
        # This is a simplified approach - in a real implementation, 
        # you might want to analyze the full video
        
        # Extract frames at 1-second intervals
        cap = cv2.VideoCapture(video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_interval = int(fps)  # 1 second interval
        
        frames = []
        frame_count = 0
        
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
                
            if frame_count % frame_interval == 0:
                # Convert frame to base64
                _, buffer = cv2.imencode('.jpg', frame)
                frame_base64 = base64.b64encode(buffer).decode('utf-8')
                frames.append(frame_base64)
                
            frame_count += 1
            
        cap.release()
        
        # Limit to 5 frames for analysis (beginning, 25%, 50%, 75%, end)
        if len(frames) > 5:
            indices = [0, len(frames)//4, len(frames)//2, 3*len(frames)//4, len(frames)-1]
            frames = [frames[i] for i in indices]
        
        # Analyze key frames
        analyses = []
        for i, frame_base64 in enumerate(frames):
            # Use Nova Lite model for image analysis
            response = self.bedrock_runtime.invoke_model(
                modelId="amazon.nova-lite-v1:0",
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 500,
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": "image/jpeg",
                                        "data": frame_base64
                                    }
                                },
                                {
                                    "type": "text",
                                    "text": f"""
                                    This is frame {i+1} of 5 from an incident playback video showing metrics during an incident.
                                    Analyze what you see in this frame, focusing on:
                                    1. What metrics are being displayed
                                    2. Any visible anomalies or patterns
                                    3. What this frame suggests about the incident at this point in time
                                    
                                    Provide a brief analysis of this specific frame.
                                    """
                                }
                            ]
                        }
                    ]
                })
            )
            
            response_body = json.loads(response['body'].read())
            frame_analysis = response_body['content'][0]['text']
            analyses.append({
                'frame_number': i+1,
                'frame_position': ['beginning', '25%', '50%', '75%', 'end'][i] if len(frames) == 5 else f"frame_{i+1}",
                'analysis': frame_analysis
            })
        
        # Synthesize overall video analysis
        synthesis_prompt = f"""
        Analyze the following key frames from an incident playback video:
        
        {json.dumps(analyses, indent=2)}
        
        Based on these frame analyses:
        1. What is the overall progression of the incident as shown in the video?
        2. What key events or changes are visible across the timeline?
        3. What insights about the root cause can be derived from this visual representation?
        
        Provide a comprehensive analysis of the incident based on the video playback.
        """
        
        # Use Nova Pro for the synthesis
        response = self.bedrock_runtime.invoke_model(
            modelId="amazon.nova-pro-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": synthesis_prompt
                            }
                        ]
                    }
                ]
            })
        )
        
        response_body = json.loads(response['body'].read())
        overall_analysis = response_body['content'][0]['text']
        
        return {
            'frame_analyses': analyses,
            'overall_analysis': overall_analysis
        }
```

## Main Application with Multi-Modal Support

```python
# main_multi_modal.py
import boto3
import json
import argparse
from datetime import datetime
import os
from aws_bedrock_setup import BedrockSetup
from log_analysis import LogAnalysisComponent
from metrics_analysis import MetricsAnalysisComponent
from dashboard_analysis import DashboardAnalysisComponent
from dashboard_visual_analysis import DashboardVisualAnalysisComponent
from video_analysis import VideoAnalysisComponent
from enhanced_rca_coordinator import EnhancedRCACoordinator

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SRE Copilot for Root Cause Analysis with Multi-Modal Support')
    parser.add_argument('--config', type=str, required=True, help='Path to configuration file')
    parser.add_argument('--incident', type=str, required=True, help='Path to incident information file')
    parser.add_argument('--output', type=str, default='rca_report.json', help='Path to output report file')
    parser.add_argument('--create-video', action='store_true', help='Create incident playback video')
    return parser.parse_args()

def load_json_file(file_path):
    """Load JSON from file"""
    with open(file_path, 'r') as f:
        return json.load(f)

def main():
    """Main entry point for the application"""
    args = parse_args()
    
    # Load configuration
    config = load_json_file(args.config)
    
    # Load incident information
    incident_info = load_json_file(args.incident)
    
    # Initialize AWS Bedrock setup
    bedrock_setup = BedrockSetup(region_name=config.get('aws_region', 'us-east-1'))
    
    # Create or use existing agents
    if config.get('create_agents', False):
        # Create new agents
        supervisor_agent_id = bedrock_setup.create_supervisor_agent(
            name=config['supervisor_agent']['name'],
            description=config['supervisor_agent']['description'],
            foundation_model_id=config['supervisor_agent']['foundation_model_id']
        )
        
        log_analysis_agent_id = bedrock_setup.create_specialized_agent(
            name=config['log_analysis_agent']['name'],
            description=config['log_analysis_agent']['description'],
            foundation_model_id=config['log_analysis_agent']['foundation_model_id'],
            specialization='log_analysis'
        )
        
        metrics_analysis_agent_id = bedrock_setup.create_specialized_agent(
            name=config['metrics_analysis_agent']['name'],
            description=config['metrics_analysis_agent']['description'],
            foundation_model_id=config['metrics_analysis_agent']['foundation_model_id'],
            specialization='metrics_analysis'
        )
        
        dashboard_analysis_agent_id = bedrock_setup.create_specialized_agent(
            name=config['dashboard_analysis_agent']['name'],
            description=config['dashboard_analysis_agent']['description'],
            foundation_model_id=config['dashboard_analysis_agent']['foundation_model_id'],
            specialization='dashboard_interpretation'
        )
        
        knowledge_base_agent_id = bedrock_setup.create_specialized_agent(
            name=config['knowledge_base_agent']['name'],
            description=config['knowledge_base_agent']['description'],
            foundation_model_id=config['knowledge_base_agent']['foundation_model_id'],
            specialization='knowledge_base'
        )
        
        # Setup multi-agent collaboration
        collaboration_id = bedrock_setup.setup_multi_agent_collaboration(
            supervisor_agent_id=supervisor_agent_id,
            collaborator_agent_ids=[
                log_analysis_agent_id,
                metrics_analysis_agent_id,
                dashboard_analysis_agent_id,
                knowledge_base_agent_id
            ]
        )
        
        # Create knowledge base
        knowledge_base_id = bedrock_setup.create_knowledge_base(
            name=config['knowledge_base']['name'],
            description=config['knowledge_base']['description'],
            data_source_config=config['knowledge_base']['data_source_config']
        )
    else:
        # Use existing agents
        supervisor_agent_id = config['supervisor_agent']['id']
        log_analysis_agent_id = config['log_analysis_agent']['id']
        metrics_analysis_agent_id = config['metrics_analysis_agent']['id']
        dashboard_analysis_agent_id = config['dashboard_analysis_agent']['id']
        knowledge_base_id = config['knowledge_base']['id']
    
    # Initialize Bedrock runtime client
    bedrock_runtime = boto3.client(
        service_name="bedrock-runtime",
        region_name=config.get('aws_region', 'us-east-1')
    )
    
    # Initialize analysis components
    log_analysis = LogAnalysisComponent(bedrock_runtime, log_analysis_agent_id)
    metrics_analysis = MetricsAnalysisComponent(bedrock_runtime, metrics_analysis_agent_id)
    dashboard_analysis = DashboardAnalysisComponent(bedrock_runtime, dashboard_analysis_agent_id)
    dashboard_visual_analysis = DashboardVisualAnalysisComponent(bedrock_runtime, dashboard_analysis_agent_id)
    video_analysis = VideoAnalysisComponent(bedrock_runtime)
    
    # Initialize RCA coordinator
    rca_coordinator = EnhancedRCACoordinator(
        bedrock_runtime=bedrock_runtime,
        supervisor_agent_id=supervisor_agent_id,
        log_analysis_component=log_analysis,
        metrics_analysis_component=metrics_analysis,
        dashboard_analysis_component=dashboard_analysis,
        dashboard_visual_analysis_component=dashboard_visual_analysis,
        knowledge_base_id=knowledge_base_id
    )
    
    # Create directories for outputs
    os.makedirs('screenshots', exist_ok=True)
    os.makedirs('videos', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Analyze incident
    report = rca_coordinator.analyze_incident(incident_info)
    
    # Create incident playback video if requested
    if args.create_video:
        # Extract incident details
        incident_id = incident_info.get('incident_id', 'unknown')
        start_time = incident_info.get('start_time')
        end_time = incident_info.get('end_time', datetime.now())
        
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time)
        
        # Collect metrics data
        metric_sources = incident_info.get('metric_sources', [])
        metrics = metrics_analysis.fetch_metrics_from_multiple_sources(
            metric_sources,
            start_time,
            end_time
        )
        
        # Create video
        video_path = f"videos/{incident_id}_playback.mp4"
        video_path = video_analysis.create_incident_playback_video(
            metrics_data=metrics,
            start_time=start_time,
            end_time=end_time,
            output_path=video_path
        )
        
        # Analyze video
        video_analysis_results = video_analysis.analyze_incident_video(video_path)
        
        # Add video analysis to report
        report['video_analysis'] = {
            'video_path': video_path,
            'frame_analyses': video_analysis_results['frame_analyses'],
            'overall_analysis': video_analysis_results['overall_analysis']
        }
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Root cause analysis completed. Report saved to {args.output}")

if __name__ == "__main__":
    main()
```

## Updated Requirements File (requirements.txt)

```
boto3>=1.28.0
pandas>=2.0.0
numpy>=1.24.0
pillow>=10.0.0
matplotlib>=3.7.0
requests>=2.31.0
selenium>=4.10.0
opencv-python>=4.8.0
```

This implementation enhances the SRE copilot with multi-modal capabilities, allowing it to process and analyze dashboard visualizations and create incident playback videos. The system can now correlate insights across different data modalities (text logs, metrics, and visual dashboards) to provide more comprehensive root cause analysis.
