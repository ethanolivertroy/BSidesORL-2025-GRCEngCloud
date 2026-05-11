#!/usr/bin/env python3
"""
FedRAMP 20x GCP Multi-Project Data Collector

USAGE:
    # Collect from multiple projects via command line
    python3 gcp_fedramp20x_collector_multi.py --projects project1,project2,project3
    
    # Collect from projects listed in a file
    python3 gcp_fedramp20x_collector_multi.py --project-file projects.csv
    
    # Specify output directory
    python3 gcp_fedramp20x_collector_multi.py --projects proj1,proj2 --output-dir /path/to/results
    
    # With service account
    export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
    python3 gcp_fedramp20x_collector_multi.py --project-file projects.csv

REQUIREMENTS:
    - Same as single project collector
    - Service account with permissions on all target projects (recommended)

OUTPUT:
    - Individual archives for each project
    - Summary report of all collections
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple
import concurrent.futures


class MultiProjectCollector:
    def __init__(self, output_dir: str = None):
        """Initialize multi-project collector"""
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = output_dir or f"fedramp_multi_collection_{self.timestamp}"
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        self.results = []
        self.summary = {
            'total_projects': 0,
            'successful': 0,
            'failed': 0,
            'collection_start': datetime.now().isoformat(),
            'errors': []
        }
    
    def read_projects_from_file(self, filepath: str) -> List[str]:
        """Read project IDs from CSV or JSON file"""
        projects = []
        
        if filepath.endswith('.csv'):
            with open(filepath, 'r') as f:
                reader = csv.reader(f)
                # Skip header if it exists
                header = next(reader, None)
                if header and header[0].lower() in ['project_id', 'project', 'id']:
                    pass  # Header row, already consumed
                else:
                    # No header, process first row
                    if header:
                        projects.append(header[0])
                
                # Read remaining rows
                for row in reader:
                    if row and row[0].strip():
                        projects.append(row[0].strip())
        
        elif filepath.endswith('.json'):
            with open(filepath, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Simple list of project IDs
                    projects = [p.strip() for p in data if isinstance(p, str)]
                elif isinstance(data, dict) and 'projects' in data:
                    # Object with projects array
                    projects = [p.strip() for p in data['projects'] if isinstance(p, str)]
        
        else:
            # Try to read as plain text, one project per line
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        projects.append(line)
        
        return projects
    
    def collect_single_project(self, project_id: str, index: int, total: int) -> Tuple[bool, str]:
        """Run collector for a single project"""
        print(f"\n{'='*60}")
        print(f"Processing project {index} of {total}: {project_id}")
        print(f"{'='*60}")
        
        try:
            # Build command
            cmd = [
                sys.executable,
                'gcp_fedramp20x_collector.py',
                '--project', project_id
            ]
            
            # Run collector
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            if result.returncode == 0:
                print(f"Successfully collected data from {project_id}")
                
                # Move the generated archive to our output directory
                # Find the generated archive
                import glob
                pattern = f"fedramp_gcp_collection_*_{project_id}_*.tar.gz"
                fallback_pattern = "fedramp_gcp_collection_*.tar.gz"
                
                archives = glob.glob(pattern)
                if not archives:
                    archives = glob.glob(fallback_pattern)
                
                if archives:
                    # Take the most recent archive
                    latest_archive = max(archives, key=os.path.getctime)
                    new_name = f"{project_id}_fedramp_collection_{self.timestamp}.tar.gz"
                    new_path = os.path.join(self.output_dir, new_name)
                    os.rename(latest_archive, new_path)
                    
                    # Also move the directory if it exists
                    dir_name = latest_archive.replace('.tar.gz', '')
                    if os.path.exists(dir_name):
                        import shutil
                        shutil.rmtree(dir_name)
                    
                    return True, f"Archive saved as: {new_name}"
                else:
                    return False, "Collection succeeded but archive not found"
            else:
                error_msg = f"Collection failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f"\nError: {result.stderr}"
                print(f"Failed to collect from {project_id}: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Exception during collection: {str(e)}"
            print(f"Failed to collect from {project_id}: {error_msg}")
            return False, error_msg
    
    def collect_projects(self, projects: List[str], parallel: bool = False):
        """Collect data from multiple projects"""
        self.summary['total_projects'] = len(projects)
        
        print(f"\nStarting collection from {len(projects)} projects")
        print(f"Output directory: {self.output_dir}")
        
        if parallel and len(projects) > 1:
            # Parallel collection (limited to 3 concurrent to avoid rate limits)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for i, project_id in enumerate(projects, 1):
                    future = executor.submit(self.collect_single_project, project_id, i, len(projects))
                    futures.append((project_id, future))
                
                for project_id, future in futures:
                    success, message = future.result()
                    self.results.append({
                        'project_id': project_id,
                        'success': success,
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    if success:
                        self.summary['successful'] += 1
                    else:
                        self.summary['failed'] += 1
                        self.summary['errors'].append({
                            'project_id': project_id,
                            'error': message
                        })
        else:
            # Sequential collection
            for i, project_id in enumerate(projects, 1):
                success, message = self.collect_single_project(project_id, i, len(projects))
                self.results.append({
                    'project_id': project_id,
                    'success': success,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                })
                
                if success:
                    self.summary['successful'] += 1
                else:
                    self.summary['failed'] += 1
                    self.summary['errors'].append({
                        'project_id': project_id,
                        'error': message
                    })
    
    def generate_summary_report(self):
        """Generate a summary report of all collections"""
        self.summary['collection_end'] = datetime.now().isoformat()
        
        # Save detailed results
        results_file = os.path.join(self.output_dir, 'collection_results.json')
        with open(results_file, 'w') as f:
            json.dump({
                'summary': self.summary,
                'results': self.results
            }, f, indent=2)
        
        # Generate human-readable summary
        summary_file = os.path.join(self.output_dir, 'collection_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(f"FedRAMP 20x Multi-Project Collection Summary\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Collection Date: {self.summary['collection_start']}\n")
            f.write(f"Total Projects: {self.summary['total_projects']}\n")
            f.write(f"Successful: {self.summary['successful']}\n")
            f.write(f"Failed: {self.summary['failed']}\n\n")
            
            if self.summary['successful'] > 0:
                f.write("Successfully Collected:\n")
                for result in self.results:
                    if result['success']:
                        f.write(f"  OK {result['project_id']}\n")
                f.write("\n")
            
            if self.summary['failed'] > 0:
                f.write("Failed Collections:\n")
                for result in self.results:
                    if not result['success']:
                        f.write(f"  FAIL {result['project_id']}: {result['message']}\n")
        
        # Print summary to console
        print(f"\n{'='*60}")
        print(f"COLLECTION SUMMARY")
        print(f"{'='*60}")
        print(f"Total Projects: {self.summary['total_projects']}")
        print(f"Successful: {self.summary['successful']}")
        print(f"Failed: {self.summary['failed']}")
        print(f"\nResults saved to: {self.output_dir}")
        print(f"Summary report: {summary_file}")
        print(f"Detailed results: {results_file}")


def main():
    parser = argparse.ArgumentParser(
        description='FedRAMP 20x GCP Multi-Project Data Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect from specific projects
  %(prog)s --projects project1,project2,project3
  
  # Collect from projects in a CSV file
  %(prog)s --project-file projects.csv
  
  # Collect with custom output directory
  %(prog)s --projects proj1,proj2 --output-dir /path/to/results
  
  # Collect in parallel (faster but uses more resources)
  %(prog)s --project-file projects.csv --parallel
        """
    )
    
    parser.add_argument('--projects', 
                       help='Comma-separated list of project IDs')
    parser.add_argument('--project-file', 
                       help='File containing project IDs (CSV, JSON, or text)')
    parser.add_argument('--output-dir', 
                       help='Directory to save all results')
    parser.add_argument('--parallel', 
                       action='store_true',
                       help='Run collections in parallel (max 3 concurrent)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.projects and not args.project_file:
        parser.error('Either --projects or --project-file must be specified')
    
    if args.projects and args.project_file:
        parser.error('Cannot specify both --projects and --project-file')
    
    # Get project list
    projects = []
    if args.projects:
        projects = [p.strip() for p in args.projects.split(',') if p.strip()]
    elif args.project_file:
        if not os.path.exists(args.project_file):
            print(f"Error: Project file not found: {args.project_file}")
            sys.exit(1)
        
        collector = MultiProjectCollector(args.output_dir)
        projects = collector.read_projects_from_file(args.project_file)
    
    if not projects:
        print("Error: No valid project IDs found")
        sys.exit(1)
    
    # Run collection
    collector = MultiProjectCollector(args.output_dir)
    collector.collect_projects(projects, parallel=args.parallel)
    collector.generate_summary_report()


if __name__ == '__main__':
    main()
