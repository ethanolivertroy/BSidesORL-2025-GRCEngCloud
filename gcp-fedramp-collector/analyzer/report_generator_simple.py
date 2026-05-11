#!/usr/bin/env python3

from datetime import datetime
import json

def generate_html_report(report_data):
    """Generate an HTML report from the analysis data"""
    
    # Determine overall score class
    overall_score = report_data['overall_score']
    if overall_score >= 80:
        overall_score_class = 'good'
    elif overall_score >= 60:
        overall_score_class = 'medium'
    else:
        overall_score_class = 'poor'
    
    # Build the HTML content step by step
    html_parts = []
    
    # Header
    html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FedRAMP 20x GCP Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f4f4f4; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
        .summary-card h3 { margin-top: 0; color: #2c3e50; }
        .score { font-size: 2em; font-weight: bold; }
        .score.good { color: #27ae60; }
        .score.medium { color: #f39c12; }
        .score.poor { color: #e74c3c; }
        .ksi-section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .ksi-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #ecf0f1; }
        .finding { padding: 10px; margin-bottom: 10px; border-left: 4px solid; background-color: #f8f9fa; }
        .finding.critical { border-color: #e74c3c; }
        .finding.high { border-color: #f39c12; }
        .finding.medium { border-color: #3498db; }
        .finding.low { border-color: #95a5a6; }
        .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; color: white; font-size: 0.8em; font-weight: bold; }
        .severity.critical { background-color: #e74c3c; }
        .severity.high { background-color: #f39c12; }
        .severity.medium { background-color: #3498db; }
        .severity.low { background-color: #95a5a6; }
        .controls { margin-top: 10px; font-size: 0.9em; color: #7f8c8d; }
        .recommendations { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .recommendation-item { padding: 10px; margin-bottom: 10px; background-color: #ecf0f1; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>""")
    
    # Header section
    html_parts.append(f"""
    <div class="header">
        <h1>FedRAMP 20x GCP Compliance Assessment Report</h1>
        <p>Assessment Date: {datetime.fromisoformat(report_data['assessment_date']).strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    """)
    
    # Summary cards
    html_parts.append(f"""
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Overall Score</h3>
            <div class="score {overall_score_class}">{overall_score:.1f}%</div>
        </div>
        <div class="summary-card">
            <h3>Total Findings</h3>
            <div class="score">{report_data['summary']['total_findings']}</div>
        </div>
        <div class="summary-card">
            <h3>Critical Findings</h3>
            <div class="score poor">{report_data['summary']['critical_findings']}</div>
        </div>
        <div class="summary-card">
            <h3>KSIs Evaluated</h3>
            <div class="score">{report_data['summary']['ksis_evaluated']}</div>
        </div>
    </div>
    """)
    
    # KSI Results
    html_parts.append("<h2>Key Security Indicator Results</h2>")
    
    for ksi_name, ksi_data in report_data['ksi_results'].items():
        score_class = 'good' if ksi_data['score'] >= 80 else 'medium' if ksi_data['score'] >= 60 else 'poor'
        
        html_parts.append(f"""
        <div class="ksi-section">
            <div class="ksi-header">
                <h3>{ksi_name}</h3>
                <div class="score {score_class}">{ksi_data['score']}%</div>
            </div>
        """)
        
        for finding in ksi_data['findings']:
            html_parts.append(f"""
            <div class="finding {finding['severity'].lower()}">
                <span class="severity {finding['severity'].lower()}">{finding['severity']}</span>
                <strong>{finding['finding']}</strong><br>
                <em>Recommendation:</em> {finding['recommendation']}
            </div>
            """)
        
        html_parts.append(f"""
            <div class="controls">
                <strong>Controls Evaluated:</strong> {', '.join(ksi_data['controls_evaluated'])}
            </div>
        </div>
        """)
    
    # Recommendations
    html_parts.append("""
    <div class="recommendations">
        <h2>Highest-Priority Fixes</h2>
    """)
    
    for rec in report_data['recommendations'][:10]:
        html_parts.append(f"""
        <div class="recommendation-item">
            <span class="severity {rec['severity'].lower()}">{rec['severity']}</span>
            <strong>{rec['ksi']}</strong>: {rec['recommendation']}
        </div>
        """)
    
    html_parts.append("</div>")
    
    # Compliance Summary Table
    html_parts.append("""
    <div class="summary-card" style="margin-top: 30px;">
        <h3>Compliance Summary</h3>
        <table>
            <tr>
                <th>KSI</th>
                <th>Score</th>
                <th>Findings</th>
                <th>Status</th>
            </tr>
    """)
    
    for ksi_name, ksi_data in report_data['ksi_results'].items():
        status = 'Pass' if ksi_data['score'] >= 80 else 'Needs Improvement' if ksi_data['score'] >= 60 else 'Fail'
        html_parts.append(f"""
            <tr>
                <td>{ksi_name}</td>
                <td>{ksi_data['score']}%</td>
                <td>{len(ksi_data['findings'])}</td>
                <td>{status}</td>
            </tr>
        """)
    
    html_parts.append("""
        </table>
    </div>
</body>
</html>
    """)
    
    return ''.join(html_parts)
