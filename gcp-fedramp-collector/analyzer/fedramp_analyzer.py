#!/usr/bin/env python3

import json
import os
import sys
import tarfile
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Tuple
from pathlib import Path
import argparse

class FedRAMPAnalyzer:
    def __init__(self, data_path: str):
        self.data_path = data_path
        self.findings = []
        self.data = {}
        self.ksi_results = {}
        
    def extract_and_load_data(self):
        """Extract tar.gz file and load JSON data"""
        if self.data_path.endswith('.tar.gz'):
            with tempfile.TemporaryDirectory() as tmpdir:
                with tarfile.open(self.data_path, 'r:gz') as tar:
                    self._safe_extract_tar(tar, Path(tmpdir))
                    
                # Find the extracted directory
                extracted_items = list(Path(tmpdir).iterdir())
                extracted_dirs = [item for item in extracted_items if item.is_dir()]
                if len(extracted_dirs) == 1:
                    self._load_json_files(extracted_dirs[0])
                else:
                    self._load_json_files(Path(tmpdir))
        else:
            self._load_json_files(Path(self.data_path))

    def _safe_extract_tar(self, tar: tarfile.TarFile, destination: Path):
        """Extract tar members only when they remain inside destination."""
        destination = destination.resolve()
        for member in tar.getmembers():
            target_path = (destination / member.name).resolve()
            if destination != target_path and destination not in target_path.parents:
                raise ValueError(f"Unsafe path in archive: {member.name}")

            if member.issym() or member.islnk():
                link_path = (target_path.parent / member.linkname).resolve()
                if destination != link_path and destination not in link_path.parents:
                    raise ValueError(f"Unsafe link in archive: {member.name}")

        tar.extractall(destination)
            
    def _load_json_files(self, base_path: Path):
        """Recursively load all JSON files"""
        for json_file in base_path.rglob('*.json'):
            relative_path = json_file.relative_to(base_path)
            category = relative_path.parts[0] if len(relative_path.parts) > 1 else 'root'
            filename = relative_path.stem
            
            try:
                with open(json_file, 'r') as f:
                    if category not in self.data:
                        self.data[category] = {}
                    self.data[category][filename] = json.load(f)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

    def analyze_ksi_iam(self):
        """Analyze KSI-IAM: Identity and Access Management"""
        findings = []
        score = 100
        
        # Check iam_data from new Python collector
        iam_data = self.data.get('iam', {}).get('iam_data', {})
        if iam_data:
            service_accounts = iam_data.get('service_accounts', [])
            iam_policy = iam_data.get('iam_policy', {})
        else:
            # Fallback to old format
            service_accounts = self.data.get('iam', {}).get('service_accounts', [])
            iam_policy = self.data.get('iam', {}).get('iam_policy', {})
        
        # Check for service accounts without proper restrictions
        for sa in service_accounts:
            if sa.get('disabled', False):
                continue
                
            # Check for default service accounts
            if 'compute@developer.gserviceaccount.com' in sa.get('email', ''):
                findings.append({
                    'severity': 'HIGH',
                    'finding': f"Default compute service account in use: {sa['email']}",
                    'recommendation': 'Create custom service accounts with minimal permissions'
                })
                score -= 10
                
        # Check extended IAM data
        iam_extended = self.data.get('iam', {}).get('iam_extended', {})
        if iam_extended:
            # Check custom roles
            custom_roles = iam_extended.get('custom_roles', [])
            overly_permissive_roles = 0
            for role in custom_roles:
                if role.get('stage') == 'DEPRECATED':
                    findings.append({
                        'severity': 'MEDIUM',
                        'finding': f"Deprecated custom role still in use: {role.get('name')}",
                        'recommendation': 'Remove or update deprecated custom roles'
                    })
                    score -= 5
                    
            # Check IAM recommendations
            recommendations = iam_extended.get('iam_recommendations', [])
            if len(recommendations) > 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f"{len(recommendations)} IAM policy recommendations available",
                    'recommendation': 'Review and implement IAM recommender suggestions for least privilege'
                })
                score -= 5
                
        # Check IAM policy for overly permissive bindings
        for binding in iam_policy.get('bindings', []):
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # Check for primitive roles
            if role in ['roles/owner', 'roles/editor']:
                findings.append({
                    'severity': 'CRITICAL',
                    'finding': f"Primitive role '{role}' assigned to {len(members)} members",
                    'recommendation': 'Use predefined or custom roles with least privilege'
                })
                score -= 15
                
            # Check for allUsers or allAuthenticatedUsers
            for member in members:
                if member in ['allUsers', 'allAuthenticatedUsers']:
                    findings.append({
                        'severity': 'CRITICAL',
                        'finding': f"Public access granted via {member} for role {role}",
                        'recommendation': 'Remove public access and use specific identities'
                    })
                    score -= 20
                    
        self.ksi_results['KSI-IAM'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['AC-2', 'AC-3', 'IA-2', 'IA-8']
        }

    def analyze_ksi_cna(self):
        """Analyze KSI-CNA: Cloud Native Architecture"""
        findings = []
        score = 100
        
        networking_resources = self.data.get('networking', {}).get('networking_resources', {})
        firewall_rules = (
            networking_resources.get('firewall_rules')
            or self.data.get('networking', {}).get('firewall_rules', [])
        )
            
        # Check firewall rules
        for rule in firewall_rules:
            # Check for overly permissive rules
            if not self._is_public_ingress_rule(rule):
                continue

            allowed = rule.get('allowed') or []
            if not allowed:
                findings.append({
                    'severity': 'CRITICAL',
                    'finding': f"Firewall rule '{rule.get('name', 'unknown')}' allows ingress from any source",
                    'recommendation': 'Restrict source IPs and protocols to minimum required'
                })
                score -= 15
                continue

            for allow in allowed:
                protocol = allow.get('IPProtocol') or allow.get('ipProtocol') or 'unknown'
                ports = allow.get('ports')
                if protocol == 'all':
                    findings.append({
                        'severity': 'CRITICAL',
                        'finding': f"Firewall rule '{rule.get('name', 'unknown')}' allows all traffic from any source",
                        'recommendation': 'Restrict source IPs and protocols to minimum required'
                    })
                    score -= 15
                elif not ports:
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f"Firewall rule '{rule.get('name', 'unknown')}' allows all ports for {protocol}",
                        'recommendation': 'Specify exact ports needed'
                    })
                    score -= 10
                else:
                    sensitive_ports = self._sensitive_public_ports(ports)
                    if sensitive_ports:
                        findings.append({
                            'severity': 'HIGH',
                            'finding': f"Firewall rule '{rule.get('name', 'unknown')}' exposes sensitive ports to the internet: {', '.join(sensitive_ports)}",
                            'recommendation': 'Restrict administrative and database ports to trusted source ranges'
                        })
                        score -= 10
                
        # Check serverless services
        serverless = self.data.get('compute', {}).get('serverless_services', {})
        if serverless:
            # Check Cloud Functions
            functions = serverless.get('cloud_functions', [])
            for func in functions:
                if func.get('serviceAccountEmail', '').endswith('@appspot.gserviceaccount.com'):
                    findings.append({
                        'severity': 'MEDIUM',
                        'finding': f"Cloud Function '{func.get('name')}' using default service account",
                        'recommendation': 'Use custom service accounts for Cloud Functions'
                    })
                    score -= 5
                    
            # Check Cloud Run services
            run_services = serverless.get('cloud_run_services', [])
            if len(run_services) > 0:
                public_services = sum(1 for s in run_services if not s.get('managed'))
                if public_services > 0:
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f"{public_services} Cloud Run services potentially exposed publicly",
                        'recommendation': 'Review Cloud Run service authentication requirements'
                    })
                    score -= 10
                    
        # Check container services
        container_services = self.data.get('containers', {}).get('container_services', {})
        if container_services:
            # Check GKE clusters
            clusters = container_services.get('gke_clusters', [])
            for cluster in clusters:
                # Check database encryption
                db_enc = cluster.get('databaseEncryption', {})
                if db_enc.get('state') != 'ENCRYPTED':
                    findings.append({
                        'severity': 'CRITICAL',
                        'finding': f"GKE cluster '{cluster.get('name')}' ETCD database not encrypted",
                        'recommendation': 'Enable Application-layer Secrets Encryption for GKE clusters'
                    })
                    score -= 15
                    
                if cluster.get('bootDiskKmsKey') == 'GOOGLE_MANAGED':
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f"GKE cluster '{cluster.get('name')}' using Google-managed boot disk encryption",
                        'recommendation': 'Use CMEK for GKE node boot disk encryption'
                    })
                    score -= 10
                        
        # Check for public IPs on instances
        compute_resources = self.data.get('compute', {}).get('compute_resources', {})
        instances = compute_resources.get('instances', []) if compute_resources else self.data.get('compute', {}).get('instances', [])
        for instance in instances:
            for interface in instance.get('networkInterfaces', []):
                if interface.get('accessConfigs'):
                    findings.append({
                        'severity': 'MEDIUM',
                        'finding': f"Instance '{instance['name']}' has public IP assigned",
                        'recommendation': 'Use Cloud NAT or Load Balancers instead of direct public IPs'
                    })
                    score -= 5
                    
        self.ksi_results['KSI-CNA'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['SC-7', 'SC-8', 'SC-23', 'SI-4']
        }

    def _is_public_ingress_rule(self, rule: Dict[str, Any]) -> bool:
        """Return True when a firewall rule permits ingress from the public internet."""
        if rule.get('direction', 'INGRESS') == 'EGRESS':
            return False

        source_ranges = rule.get('sourceRanges') or rule.get('source_ranges') or []
        return '0.0.0.0/0' in source_ranges or '::/0' in source_ranges

    def _sensitive_public_ports(self, ports: List[str]) -> List[str]:
        """Identify common administrative/database ports exposed by a public rule."""
        sensitive_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            1433: 'SQL Server',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5984: 'CouchDB',
            6379: 'Redis',
            9200: 'Elasticsearch',
            11211: 'Memcached',
            27017: 'MongoDB'
        }
        exposed = []

        for port_spec in ports:
            try:
                if '-' in str(port_spec):
                    start, end = [int(part) for part in str(port_spec).split('-', 1)]
                    for port, service in sensitive_ports.items():
                        if start <= port <= end:
                            exposed.append(f"{port}/{service}")
                else:
                    port = int(port_spec)
                    if port in sensitive_ports:
                        exposed.append(f"{port}/{sensitive_ports[port]}")
            except (TypeError, ValueError):
                continue

        return sorted(set(exposed))

    def analyze_ksi_mla(self):
        """Analyze KSI-MLA: Monitoring, Logging, and Auditing"""
        findings = []
        score = 100
        
        # Check new logging_monitoring format first
        logging_monitoring = self.data.get('monitoring', {}).get('logging_monitoring', {})
        if logging_monitoring:
            log_sinks = logging_monitoring.get('log_sinks', [])
            alert_policies = logging_monitoring.get('alert_policies', [])
        else:
            # Fallback to old format
            log_sinks = self.data.get('logging', {}).get('log_sinks', [])
            alert_policies = self.data.get('monitoring', {}).get('alert_policies', [])
            
        # Check extended monitoring data
        monitoring_extended = self.data.get('monitoring', {}).get('monitoring_extended', {})
        if monitoring_extended:
            audit_configs = monitoring_extended.get('audit_log_configs', [])
            log_metrics = monitoring_extended.get('log_metrics', [])
            uptime_checks = monitoring_extended.get('uptime_checks', [])
            dashboards = monitoring_extended.get('monitoring_dashboards', [])
        else:
            audit_configs = self.data.get('logging', {}).get('audit_configs', [])
            log_metrics = []
            uptime_checks = []
            dashboards = []
        
        # Check for audit logging configuration
        if not audit_configs:
            findings.append({
                'severity': 'CRITICAL',
                'finding': 'No audit logging configuration found',
                'recommendation': 'Enable audit logging for all services'
            })
            score -= 30
            
        # Check log sinks
        if not log_sinks:
            findings.append({
                'severity': 'HIGH',
                'finding': 'No log sinks configured',
                'recommendation': 'Configure log sinks to export logs to long-term storage'
            })
            score -= 20
            
        # Check log metrics
        if len(log_metrics) == 0:
            findings.append({
                'severity': 'MEDIUM',
                'finding': 'No custom log metrics configured',
                'recommendation': 'Create log-based metrics for security monitoring'
            })
            score -= 10
            
        # Check uptime monitoring
        compute_resources = self.data.get('compute', {}).get('compute_resources', {})
        instances = compute_resources.get('instances', []) if compute_resources else self.data.get('compute', {}).get('instances', [])
        
        if len(instances) > 0 and len(uptime_checks) == 0:
            findings.append({
                'severity': 'MEDIUM',
                'finding': 'No uptime checks configured for compute instances',
                'recommendation': 'Configure uptime checks for critical services'
            })
            score -= 10
            
        # Check monitoring alerts
        if len(alert_policies) < 5:
            findings.append({
                'severity': 'MEDIUM',
                'finding': f'Only {len(alert_policies)} alert policies configured',
                'recommendation': 'Configure alert policies for security events'
            })
            score -= 10
            
        self.ksi_results['KSI-MLA'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['AU-2', 'AU-3', 'AU-4', 'AU-6', 'AU-12']
        }

    def analyze_ksi_svc(self):
        """Analyze KSI-SVC: Service Configuration"""
        findings = []
        score = 100
        
        # Check for unnecessary APIs enabled (handle both old and new format)
        enabled_apis = self.data.get('security', {}).get('enabled_apis', [])
        # Also check new security_services format
        if not enabled_apis:
            security_services = self.data.get('security', {}).get('security_services', {})
            enabled_apis = security_services.get('enabled_apis', [])
            
        risky_apis = [
            'deploymentmanager.googleapis.com',
            'runtimeconfig.googleapis.com',
            'sourcerepo.googleapis.com'
        ]
        
        for api in enabled_apis:
            # Handle both old format (api.get('config', {}).get('name')) and new format (api.get('name'))
            api_name = api.get('name', '') or api.get('config', {}).get('name', '')
            if any(risky in api_name for risky in risky_apis):
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f"Potentially risky API enabled: {api_name}",
                    'recommendation': 'Disable APIs that are not actively used'
                })
                score -= 5
                
        # Check for encryption policy configuration
        encryption_policy = self.data.get('kms', {}).get('encryption_policy_summary', {})
        if encryption_policy.get('kms_enabled') != True:
            findings.append({
                'severity': 'HIGH',
                'finding': 'KMS service not enabled or no customer-managed encryption keys configured',
                'recommendation': 'Enable Cloud KMS and implement customer-managed encryption for sensitive data'
            })
            score -= 15
            
        # Check organization encryption policies
        org_policies = self.data.get('kms', {}).get('org_encryption_policies', {})
        if org_policies.get('status') == 'no_org_policy':
            findings.append({
                'severity': 'MEDIUM',
                'finding': 'No organization-level encryption policies enforced',
                'recommendation': 'Implement organization policies to enforce encryption requirements'
            })
            score -= 10
            
        # Prefer the collector's encryption summary when it is available.
        encryption_assessment = self.data.get('security', {}).get('encryption_assessment', {})
        if encryption_assessment:
            summary = encryption_assessment.get('summary', {})
            by_service = encryption_assessment.get('by_service', {})
            
            # Check storage encryption
            storage_enc = by_service.get('storage', {})
            if storage_enc.get('buckets_google_managed', 0) > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'finding': f"{storage_enc['buckets_google_managed']} of {storage_enc.get('buckets_total', 0)} storage buckets using Google-managed encryption",
                    'recommendation': 'Enable customer-managed encryption (CMEK) for all storage buckets'
                })
                score -= 20
                
            # Check compute disk encryption
            compute_enc = by_service.get('compute', {})
            if compute_enc.get('disks_google_managed', 0) > 0:
                findings.append({
                    'severity': 'HIGH',
                    'finding': f"{compute_enc['disks_google_managed']} of {compute_enc.get('disks_total', 0)} compute disks using Google-managed encryption",
                    'recommendation': 'Use customer-managed encryption keys (CMEK) for all compute disks'
                })
                score -= 10
                
            # Check SQL encryption
            sql_enc = by_service.get('sql', {})
            if sql_enc.get('instances_google_managed', 0) > 0:
                findings.append({
                    'severity': 'HIGH',
                    'finding': f"{sql_enc['instances_google_managed']} of {sql_enc.get('instances_total', 0)} SQL instances using Google-managed encryption",
                    'recommendation': 'Enable CMEK for all Cloud SQL instances'
                })
                score -= 10
                
            # Add recommendations from assessment
            for rec in encryption_assessment.get('recommendations', []):
                findings.append({
                    'severity': rec.get('severity', 'MEDIUM'),
                    'finding': rec.get('finding', ''),
                    'recommendation': rec.get('recommendation', '')
                })
                if rec.get('severity') == 'HIGH':
                    score -= 10
                elif rec.get('severity') == 'CRITICAL':
                    score -= 15
        else:
            # Fallback to checking individual encryption data
            # Check storage bucket encryption
            bulk_buckets = self.data.get('storage', {}).get('all_buckets_encryption', [])
            if bulk_buckets:
                google_managed_buckets = sum(1 for b in bulk_buckets if b.get('encryption') == 'GOOGLE_MANAGED')
                if google_managed_buckets > 0:
                    findings.append({
                        'severity': 'CRITICAL',
                        'finding': f'{google_managed_buckets} storage buckets without customer-managed encryption',
                        'recommendation': 'Enable customer-managed encryption (CMEK) for all storage buckets'
                    })
                    score -= 20
            
            # Check compute disk encryption from all_disks_encryption
            all_disks = self.data.get('compute', {}).get('all_disks_encryption', [])
            if all_disks:
                google_managed_disks = sum(1 for d in all_disks if d.get('encryption') == 'GOOGLE_MANAGED')
                if google_managed_disks > 0:
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f'{google_managed_disks} compute disks using Google-managed encryption',
                        'recommendation': 'Use customer-managed encryption keys (CMEK) for all compute disks'
                    })
                    score -= 10
            
        # Check encryption summary
        encryption_summary = self.data.get('security', {}).get('encryption_summary', {})
        if encryption_summary.get('assessment_type') == 'encryption_configuration':
            # Add informational note about encryption assessment
            findings.append({
                'severity': 'INFO',
                'finding': 'Encryption assessment performed without collecting actual key details',
                'recommendation': 'Review encryption configurations across all resource types'
            })
            
        # Check security compliance data
        security_compliance = self.data.get('security', {}).get('security_compliance', {})
        if security_compliance:
            # Check API keys
            api_keys = security_compliance.get('api_keys', [])
            unrestricted_keys = sum(1 for k in api_keys if not k.get('restrictions'))
            if unrestricted_keys > 0:
                findings.append({
                    'severity': 'HIGH',
                    'finding': f'{unrestricted_keys} API keys without restrictions',
                    'recommendation': 'Add IP and API restrictions to all API keys'
                })
                score -= 10
                
            # Check container vulnerabilities
            vulnerabilities = security_compliance.get('container_vulnerabilities', {})
            if vulnerabilities.get('critical', 0) > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'finding': f"{vulnerabilities['critical']} critical vulnerabilities in container images",
                    'recommendation': 'Update base images and dependencies to patch critical vulnerabilities'
                })
                score -= 20
            elif vulnerabilities.get('high', 0) > 0:
                findings.append({
                    'severity': 'HIGH',
                    'finding': f"{vulnerabilities['high']} high severity vulnerabilities in container images",
                    'recommendation': 'Update container images to address high severity vulnerabilities'
                })
                score -= 10
                
            # Check VPC Service Controls
            perimeters = security_compliance.get('vpc_service_perimeters', [])
            if len(perimeters) == 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': 'No VPC Service Controls perimeters configured',
                    'recommendation': 'Implement VPC Service Controls for data exfiltration protection'
                })
                score -= 10
                
        self.ksi_results['KSI-SVC'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['CM-2', 'CM-6', 'CM-7', 'SC-12', 'SC-13']
        }

    def analyze_ksi_piy(self):
        """Analyze KSI-PIY: Policy and Inventory"""
        findings = []
        score = 100
        
        security_data = self.data.get('security', {})
        security_compliance = security_data.get('security_compliance', {})
        asset_summary = security_data.get('asset_inventory_summary')
        if asset_summary is None and security_compliance:
            asset_summary = security_compliance.get('asset_inventory_summary')

        # Check asset inventory summary from new collector
        if asset_summary is not None:
            # Just having the summary means inventory is being tracked
            if not asset_summary:
                findings.append({
                    'severity': 'HIGH',
                    'finding': 'No asset inventory tracking configured',
                    'recommendation': 'Enable Cloud Asset Inventory so resources can be queried consistently'
                })
                score -= 15
        else:
            # Check for untagged resources (old format)
            asset_inventory = self.data.get('security', {}).get('asset_inventory', [])
            untagged_count = 0
            
            for asset in asset_inventory:
                labels = asset.get('labels', {})
                if not labels or len(labels) < 2:
                    untagged_count += 1
                    
            if untagged_count > 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'finding': f'{untagged_count} resources found without proper labeling',
                    'recommendation': 'Implement consistent labeling strategy for all resources'
                })
                score -= 10
            
        # Check for orphaned resources
        disks = self.data.get('compute', {}).get('disks', [])
        for disk in disks:
            if not disk.get('users'):
                findings.append({
                    'severity': 'LOW',
                    'finding': f"Orphaned disk found: {disk['name']}",
                    'recommendation': 'Remove unused disks to reduce attack surface'
                })
                score -= 2
                
        self.ksi_results['KSI-PIY'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['CM-8', 'PM-5', 'RA-5']
        }

    def analyze_ksi_rpl(self):
        """Analyze KSI-RPL: Recovery Planning"""
        findings = []
        score = 100
        configured_backup_policies = []
        
        # Check backup and build services from new collector
        backup_services = self.data.get('backup', {}).get('backup_build_services', {})
        if backup_services:
            # Check backup policies
            backup_policies = backup_services.get('backup_policies', [])
            configured_backup_policies = backup_policies
            snapshots = backup_services.get('compute_snapshots', [])
            backup_plans = backup_services.get('backup_plans', [])
            
            # Get instance count from compute resources
            compute_resources = self.data.get('compute', {}).get('compute_resources', {})
            instances = compute_resources.get('instances', []) if compute_resources else self.data.get('compute', {}).get('instances', [])
            
            if len(instances) > 0:
                if len(backup_policies) == 0 and len(snapshots) == 0:
                    findings.append({
                        'severity': 'CRITICAL',
                        'finding': 'No backup policies or snapshots found for compute instances',
                        'recommendation': 'Implement automated backup policies for all critical instances'
                    })
                    score -= 20
                elif len(backup_policies) > 0:
                    findings.append({
                        'severity': 'INFO',
                        'finding': f'{len(backup_policies)} backup policies configured',
                        'recommendation': 'Ensure all critical resources are covered by backup policies'
                    })
                    
            # Check database backups
            database_services = self.data.get('database', {}).get('database_services', {})
            if database_services:
                total_dbs = len(database_services.get('sql_databases', [])) + \
                           len(database_services.get('spanner_instances', [])) + \
                           len(database_services.get('bigtable_instances', []))
                           
                if total_dbs > 0 and len(backup_plans) == 0:
                    findings.append({
                        'severity': 'HIGH',
                        'finding': f'{total_dbs} databases found without backup plans',
                        'recommendation': 'Configure automated backups for all database instances'
                    })
                    score -= 15
        else:
            # Fallback to old format
            snapshots = self.data.get('compute', {}).get('snapshots', [])
            instances = self.data.get('compute', {}).get('instances', [])
            configured_backup_policies = self.data.get('storage', {}).get('backup_policies', [])
            
            if len(instances) > 0 and len(snapshots) == 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'finding': 'No snapshots found for compute instances',
                    'recommendation': 'Implement automated snapshot policies for all instances'
                })
                score -= 25
            
        # Check backup policies
        if not configured_backup_policies:
            findings.append({
                'severity': 'HIGH',
                'finding': 'No automated backup policies configured',
                'recommendation': 'Create snapshot schedules for critical resources'
            })
            score -= 20
            
        self.ksi_results['KSI-RPL'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['CP-9', 'CP-10', 'CP-6', 'CP-7']
        }

    def analyze_ksi_cmt(self):
        """Analyze KSI-CMT: Change Management"""
        findings = []
        score = 100
        
        # Check patch management from extended compute resources
        compute_extended = self.data.get('compute', {}).get('compute_extended', {})
        if compute_extended:
            patch_jobs = compute_extended.get('os_patch_jobs', [])
            patch_deployments = compute_extended.get('os_patch_deployments', [])
        else:
            # Fallback to old format
            patch_jobs = self.data.get('compute', {}).get('os_patch_jobs', [])
            patch_deployments = self.data.get('compute', {}).get('os_patch_deployments', [])
        
        if not patch_deployments:
            findings.append({
                'severity': 'HIGH',
                'finding': 'No OS patch deployments configured',
                'recommendation': 'Implement automated OS patching policies for all instances'
            })
            score -= 15
                
        # Check Cloud Build for CI/CD
        build_services = self.data.get('backup', {}).get('backup_build_services', {})
        if build_services:
            builds = build_services.get('cloud_builds', [])
            build_triggers = build_services.get('build_triggers', [])
            
            if len(build_triggers) > 0:
                disabled_triggers = sum(1 for t in build_triggers if t.get('disabled', False))
                if disabled_triggers > 0:
                    findings.append({
                        'severity': 'LOW',
                        'finding': f'{disabled_triggers} Cloud Build triggers are disabled',
                        'recommendation': 'Review and remove unnecessary build triggers'
                    })
                    score -= 5
            
        # Check activity logs for unauthorized changes
        activity_logs = self.data.get('logging', {}).get('activity_logs', [])
        suspicious_activities = []
        
        for log in activity_logs:
            method = log.get('protoPayload', {}).get('methodName', '')
            if 'delete' in method.lower() or 'remove' in method.lower():
                suspicious_activities.append(method)
                
        if len(suspicious_activities) > 10:
            findings.append({
                'severity': 'MEDIUM',
                'finding': f'High number of deletion activities detected: {len(suspicious_activities)}',
                'recommendation': 'Review change management procedures'
            })
            score -= 10
            
        self.ksi_results['KSI-CMT'] = {
            'score': max(0, score),
            'findings': findings,
            'controls_evaluated': ['CM-3', 'CM-4', 'CM-5', 'CM-11']
        }

    def generate_report(self):
        """Generate report data"""
        report = {
            'assessment_date': datetime.now().isoformat(),
            'overall_score': sum(ksi['score'] for ksi in self.ksi_results.values()) / len(self.ksi_results),
            'ksi_results': self.ksi_results,
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
        
    def _generate_summary(self):
        """Generate executive summary"""
        total_findings = sum(len(ksi['findings']) for ksi in self.ksi_results.values())
        critical_findings = sum(
            1 for ksi in self.ksi_results.values() 
            for finding in ksi['findings'] 
            if finding['severity'] == 'CRITICAL'
        )
        
        return {
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'ksis_evaluated': len(self.ksi_results),
            'lowest_scoring_ksi': min(self.ksi_results.items(), key=lambda x: x[1]['score'])[0]
        }
        
    def _generate_recommendations(self):
        """Generate prioritized recommendations"""
        all_recommendations = []
        
        for ksi_name, ksi_data in self.ksi_results.items():
            for finding in ksi_data['findings']:
                all_recommendations.append({
                    'ksi': ksi_name,
                    'severity': finding['severity'],
                    'recommendation': finding['recommendation']
                })
                
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_recommendations.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return all_recommendations[:10]  # Top 10 recommendations

    def run_analysis(self):
        """Run all KSI analyses"""
        print("Loading collected data...")
        self.extract_and_load_data()
        
        print("Analyzing KSI-IAM...")
        self.analyze_ksi_iam()
        
        print("Analyzing KSI-CNA...")
        self.analyze_ksi_cna()
        
        print("Analyzing KSI-MLA...")
        self.analyze_ksi_mla()
        
        print("Analyzing KSI-SVC...")
        self.analyze_ksi_svc()
        
        print("Analyzing KSI-PIY...")
        self.analyze_ksi_piy()
        
        print("Analyzing KSI-RPL...")
        self.analyze_ksi_rpl()
        
        print("Analyzing KSI-CMT...")
        self.analyze_ksi_cmt()
        
        print("Generating report...")
        return self.generate_report()


def main():
    parser = argparse.ArgumentParser(description='FedRAMP 20x GCP Compliance Analyzer')
    parser.add_argument('data_file', help='Path to collected data (tar.gz or directory)')
    parser.add_argument('-o', '--output', default='fedramp_analysis_report.json', 
                       help='Output report filename')
    parser.add_argument('-f', '--format', choices=['json', 'html'], default='json',
                       help='Output format')
    
    args = parser.parse_args()
    
    analyzer = FedRAMPAnalyzer(args.data_file)
    report = analyzer.run_analysis()
    
    if args.format == 'json':
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
    else:
        # Generate HTML report
        from .report_generator_simple import generate_html_report
        html_content = generate_html_report(report)
        with open(args.output.replace('.json', '.html'), 'w') as f:
            f.write(html_content)
    
    print(f"\nAnalysis complete! Report saved to: {args.output}")
    print(f"Overall compliance score: {report['overall_score']:.1f}%")
    print(f"Total findings: {report['summary']['total_findings']}")
    print(f"Critical findings: {report['summary']['critical_findings']}")


if __name__ == '__main__':
    main()
