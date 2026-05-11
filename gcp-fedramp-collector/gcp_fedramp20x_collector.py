#!/usr/bin/env python3
"""
FedRAMP 20x GCP Data Collector

Historical note:
    This demo was written during the FedRAMP 20x pilot period around
    September 26, 2025. Treat its KSI mappings and scoring as a historical
    implementation example, not as current authoritative FedRAMP guidance.

USAGE:
    python3 gcp_fedramp20x_collector.py                    # Uses default project
    python3 gcp_fedramp20x_collector.py --project PROJECT  # Specific project
    
    # With service account:
    export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
    python3 gcp_fedramp20x_collector.py --project PROJECT

REQUIREMENTS:
    - Python 3.7+
    - pip3 install -r requirements.txt
    - GCP authentication (gcloud auth application-default login)

OUTPUT:
    fedramp_gcp_collection_PROJECT_ID_YYYYMMDD_HHMMSS.tar.gz
"""

import json
import os
import sys
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
import argparse
from typing import Dict, List, Any

# Import Google Cloud libraries
try:
    from google.cloud import compute_v1
    from google.cloud import storage
    from google.cloud import logging as cloud_logging
    from google.cloud import kms
    from google.cloud import pubsub_v1
    from google.cloud import container_v1
    from google.cloud import secretmanager
    from google.cloud import monitoring_v3
    from google.api_core import exceptions
    import google.auth
except ImportError:
    print("Error: Google Cloud Python SDK not installed.")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)


class FedRAMP20xCollector:
    def __init__(self, project_id: str = None):
        """Initialize the collector with project credentials"""
        try:
            self.credentials, detected_project = google.auth.default()
            self.project_id = project_id or detected_project
            
            if not self.project_id:
                print("Error: No project ID specified or detected.")
                print("Please provide --project PROJECT_ID or set up gcloud:")
                print("  gcloud auth application-default login")
                print("  gcloud config set project YOUR_PROJECT_ID")
                sys.exit(1)
                
        except google.auth.exceptions.DefaultCredentialsError:
            print("\nError: Google Cloud credentials not found!")
            print("\nPlease authenticate using one of these methods:")
            print("\n1. For Cloud Shell or local development:")
            print("   gcloud auth application-default login")
            print("\n2. For service account:")
            print("   export GOOGLE_APPLICATION_CREDENTIALS='/path/to/key.json'")
            sys.exit(1)
            
        project_slug = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in self.project_id)
        self.output_dir = f"fedramp_gcp_collection_{project_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Create all necessary subdirectories
        for subdir in ['iam', 'compute', 'networking', 'logging', 'storage', 'security', 
                       'kms', 'monitoring', 'database', 'containers', 'bigdata', 'aiml', 
                       'backup', 'serverless', 'access_analysis', 'security_posture', 'change_detection']:
            Path(self.output_dir, subdir).mkdir(exist_ok=True)
        
        # Track service accounts used by compute resources
        self._compute_service_accounts = set()
        
        # Initialize clients
        self.storage_client = storage.Client(project=self.project_id)
        self.compute_client = compute_v1.InstancesClient()
        self.disks_client = compute_v1.DisksClient()
        self.networks_client = compute_v1.NetworksClient()
        self.firewalls_client = compute_v1.FirewallsClient()
        self.logging_client = cloud_logging.Client(project=self.project_id)
        self.kms_client = kms.KeyManagementServiceClient()
        self.pubsub_client = pubsub_v1.PublisherClient()
        self.container_client = container_v1.ClusterManagerClient()
        self.secrets_client = secretmanager.SecretManagerServiceClient()
        
    def save_json(self, category: str, filename: str, data: Any):
        """Save data to JSON file"""
        category_dir = Path(self.output_dir) / category
        category_dir.mkdir(exist_ok=True)
        
        filepath = category_dir / f"{filename}.json"
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"Collected {category}/{filename}")
        
    def collect_storage_encryption(self) -> List[Dict]:
        """Collect storage bucket encryption status with lifecycle and versioning"""
        print("\n[Storage] Checking bucket encryption, lifecycle, and versioning...")
        buckets_info = []
        
        try:
            # Get all buckets in one call
            buckets = list(self.storage_client.list_buckets())
            
            # Use ThreadPoolExecutor for parallel bucket checks
            def check_bucket_details(bucket):
                info = {
                    'name': bucket.name,
                    'location': bucket.location,
                    'storageClass': bucket.storage_class,
                    'uniformBucketLevelAccess': getattr(bucket.iam_configuration, 'uniform_bucket_level_access_enabled', False),
                    'creationTime': bucket.time_created.isoformat() if bucket.time_created else None,
                    'labels': dict(bucket.labels) if bucket.labels else {}
                }
                
                # Encryption
                if bucket.default_kms_key_name:
                    info['encryption'] = 'CMEK'
                else:
                    info['encryption'] = 'GOOGLE_MANAGED'
                
                # Versioning
                info['versioning'] = {
                    'enabled': bucket.versioning_enabled if hasattr(bucket, 'versioning_enabled') else False
                }
                
                # Lifecycle rules
                lifecycle_rules = []
                if bucket.lifecycle_rules:
                    for rule in bucket.lifecycle_rules:
                        rule_info = {
                            'action': rule.get('action', {}).get('type'),
                            'condition': {}
                        }
                        condition = rule.get('condition', {})
                        if 'age' in condition:
                            rule_info['condition']['age'] = condition['age']
                        if 'matchesStorageClass' in condition:
                            rule_info['condition']['matchesStorageClass'] = condition['matchesStorageClass']
                        if 'isLive' in condition:
                            rule_info['condition']['isLive'] = condition['isLive']
                        lifecycle_rules.append(rule_info)
                info['lifecycleRules'] = lifecycle_rules
                
                # Retention policy
                if hasattr(bucket, 'retention_period') and bucket.retention_period:
                    info['retentionPolicy'] = {
                        'retentionPeriod': bucket.retention_period,
                        'isLocked': getattr(bucket, 'retention_policy_locked', False)
                    }
                else:
                    info['retentionPolicy'] = None
                
                # Public access prevention
                info['publicAccessPrevention'] = bucket.iam_configuration.public_access_prevention if hasattr(bucket.iam_configuration, 'public_access_prevention') else 'unspecified'
                
                # CORS configuration
                info['corsConfigured'] = bool(bucket.cors)
                
                # Logging
                if hasattr(bucket, 'logging') and bucket.logging:
                    info['logging'] = {
                        'logBucket': bucket.logging.log_bucket if hasattr(bucket.logging, 'log_bucket') else None,
                        'logObjectPrefix': bucket.logging.log_object_prefix if hasattr(bucket.logging, 'log_object_prefix') else None
                    }
                else:
                    info['logging'] = {
                        'logBucket': None,
                        'logObjectPrefix': None
                    }
                
                # Autoclass
                if hasattr(bucket, 'autoclass'):
                    info['autoclass'] = {
                        'enabled': bucket.autoclass.get('enabled', False),
                        'toggleTime': bucket.autoclass.get('toggleTime')
                    }
                    
                return info
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                buckets_info = list(executor.map(check_bucket_details, buckets))
                
            print(f"Found {len(buckets_info)} storage buckets with detailed configuration")
                
        except Exception as e:
            print(f"Error collecting storage details: {e}")
            import traceback
            traceback.print_exc()
            
        return buckets_info
    
    def collect_compute_disk_encryption(self) -> List[Dict]:
        """Collect compute disk encryption status"""
        print("\n[Compute] Checking disk encryption...")
        disks_info = []
        
        try:
            # Aggregate all disks across zones
            aggregated_list = self.disks_client.aggregated_list(project=self.project_id)
            
            for zone, response in aggregated_list:
                if response.disks:
                    for disk in response.disks:
                        info = {
                            'name': disk.name,
                            'zone': zone.split('/')[-1],
                            'sizeGb': disk.size_gb,
                            'type': disk.type.split('/')[-1] if disk.type else 'unknown'
                        }
                        
                        # Check encryption
                        if disk.disk_encryption_key:
                            info['encryption'] = 'CMEK'
                        else:
                            info['encryption'] = 'GOOGLE_MANAGED'
                            
                        disks_info.append(info)
                        
        except Exception as e:
            print(f"Error collecting disk encryption: {e}")
            
        return disks_info
    
    def collect_sql_encryption(self) -> List[Dict]:
        """Collect Cloud SQL encryption status using REST API"""
        print("\n[Database] Checking SQL instance encryption...")
        sql_info = []
        
        try:
            # Use googleapiclient for Cloud SQL
            from googleapiclient import discovery
            service = discovery.build('sqladmin', 'v1', credentials=self.credentials)
            
            request = service.instances().list(project=self.project_id)
            response = request.execute()
            
            if 'items' in response:
                for instance in response['items']:
                    info = {
                        'name': instance.get('name'),
                        'databaseVersion': instance.get('databaseVersion'),
                        'region': instance.get('region')
                    }
                    
                    # Check encryption
                    disk_config = instance.get('diskEncryptionConfiguration', {})
                    if disk_config.get('kmsKeyName'):
                        info['encryption'] = 'CMEK'
                    else:
                        info['encryption'] = 'GOOGLE_MANAGED'
                        
                    sql_info.append(info)
                    
        except Exception as e:
            if "accessNotConfigured" in str(e):
                print("Note: Cloud SQL Admin API not enabled - skipping SQL instances")
            else:
                print(f"Error collecting SQL encryption: {e}")
            
        return sql_info
    
    def collect_iam_data(self) -> Dict[str, Any]:
        """Collect enhanced IAM data with key ages and activity"""
        print("\n[IAM] Collecting enhanced identity and access data...")
        try:
            from googleapiclient import discovery
            service = discovery.build('iam', 'v1', credentials=self.credentials)
            
            # Get service accounts with key details
            sa_response = service.projects().serviceAccounts().list(
                name=f'projects/{self.project_id}'
            ).execute()
            
            enhanced_service_accounts = []
            for account in sa_response.get('accounts', []):
                sa_info = {
                    'email': account.get('email'),
                    'displayName': account.get('displayName'),
                    'name': account.get('name'),
                    'disabled': account.get('disabled', False),
                    'keys': [],
                    'keyAnalysis': {
                        'totalKeys': 0,
                        'userManagedKeys': 0,
                        'systemManagedKeys': 0,
                        'oldestKeyAgeDays': 0,
                        'keysOver90Days': 0,
                        'keysOver365Days': 0
                    }
                }
                
                # Get service account keys
                try:
                    keys_response = service.projects().serviceAccounts().keys().list(
                        name=account['name']
                    ).execute()
                    
                    current_time = datetime.now(timezone.utc)
                    oldest_key_age = 0
                    
                    for key in keys_response.get('keys', []):
                        key_info = {
                            'name': key.get('name', '').split('/')[-1],
                            'keyType': key.get('keyType'),
                            'keyAlgorithm': key.get('keyAlgorithm'),
                            'validAfterTime': key.get('validAfterTime'),
                            'validBeforeTime': key.get('validBeforeTime')
                        }
                        
                        # Calculate key age
                        if key.get('validAfterTime'):
                            try:
                                valid_after = datetime.fromisoformat(key['validAfterTime'].replace('Z', '+00:00'))
                                key_age_days = (current_time - valid_after).days
                                key_info['ageInDays'] = key_age_days
                                
                                if key_age_days > oldest_key_age:
                                    oldest_key_age = key_age_days
                                
                                if key_age_days > 90:
                                    sa_info['keyAnalysis']['keysOver90Days'] += 1
                                if key_age_days > 365:
                                    sa_info['keyAnalysis']['keysOver365Days'] += 1
                            except:
                                pass
                        
                        sa_info['keys'].append(key_info)
                        sa_info['keyAnalysis']['totalKeys'] += 1
                        
                        if key.get('keyType') == 'USER_MANAGED':
                            sa_info['keyAnalysis']['userManagedKeys'] += 1
                        else:
                            sa_info['keyAnalysis']['systemManagedKeys'] += 1
                    
                    sa_info['keyAnalysis']['oldestKeyAgeDays'] = oldest_key_age
                    
                except Exception as e:
                    print(f"Could not get keys for {account.get('email')}: {e}")
                
                enhanced_service_accounts.append(sa_info)
            
            # Get IAM policy with analysis
            iam_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            policy_response = iam_service.projects().getIamPolicy(
                resource=f'projects/{self.project_id}'
            ).execute()
            
            # Analyze IAM policy
            policy_analysis = {
                'totalBindings': len(policy_response.get('bindings', [])),
                'primitiveRoles': {'Owner': [], 'Editor': [], 'Viewer': []},
                'serviceAccountsWithPrimitiveRoles': [],
                'externalMembers': [],
                'allUsers': False,
                'allAuthenticatedUsers': False
            }
            
            for binding in policy_response.get('bindings', []):
                role = binding.get('role', '')
                
                # Check for primitive roles
                if role == 'roles/owner':
                    policy_analysis['primitiveRoles']['Owner'].extend(binding.get('members', []))
                elif role == 'roles/editor':
                    policy_analysis['primitiveRoles']['Editor'].extend(binding.get('members', []))
                elif role == 'roles/viewer':
                    policy_analysis['primitiveRoles']['Viewer'].extend(binding.get('members', []))
                
                # Check members
                for member in binding.get('members', []):
                    if member == 'allUsers':
                        policy_analysis['allUsers'] = True
                    elif member == 'allAuthenticatedUsers':
                        policy_analysis['allAuthenticatedUsers'] = True
                    elif not member.endswith('.gserviceaccount.com') and '@' in member and not member.startswith('serviceAccount:'):
                        # External user
                        if member not in policy_analysis['externalMembers']:
                            policy_analysis['externalMembers'].append(member)
                    elif member.startswith('serviceAccount:') and role in ['roles/owner', 'roles/editor']:
                        policy_analysis['serviceAccountsWithPrimitiveRoles'].append({
                            'serviceAccount': member,
                            'role': role
                        })
            
            return {
                'service_accounts': enhanced_service_accounts,
                'iam_policy': policy_response,
                'policy_analysis': policy_analysis
            }
        except Exception as e:
            print(f"Error collecting IAM data: {e}")
            return {}
    
    def collect_compute_resources(self) -> Dict[str, Any]:
        """Collect compute resources with enhanced metadata"""
        print("\n[Compute] Collecting compute resources with enhanced metadata...")
        results = {}
        
        try:
            # Enhanced Instances collection with metadata, labels, service accounts
            instances = []
            aggregated_list = self.compute_client.aggregated_list(project=self.project_id)
            for zone, response in aggregated_list:
                if response.instances:
                    for inst in response.instances:
                        instance_info = {
                            'name': inst.name,
                            'zone': zone.split('/')[-1],
                            'machineType': inst.machine_type.split('/')[-1] if inst.machine_type else 'unknown',
                            'status': inst.status,
                            'labels': dict(inst.labels) if inst.labels else {},
                            'creationTimestamp': inst.creation_timestamp,
                            'lastStartTimestamp': inst.last_start_timestamp,
                            # Metadata
                            'metadata': {},
                            # Network interfaces and public IPs
                            'networkInterfaces': [],
                            # Service accounts
                            'serviceAccounts': [],
                            # Disk encryption
                            'diskEncryption': [],
                            # Security features
                            'shieldedInstanceConfig': {},
                            'confidentialInstanceConfig': {},
                            # Scheduling
                            'preemptible': inst.scheduling.preemptible if inst.scheduling else False,
                            'automaticRestart': inst.scheduling.automatic_restart if inst.scheduling else True
                        }
                        
                        # Extract important metadata
                        if inst.metadata and inst.metadata.items:
                            for item in inst.metadata.items:
                                if item.key in ['enable-oslogin', 'enable-osconfig', 'startup-script', 
                                               'serial-port-enable', 'block-project-ssh-keys']:
                                    instance_info['metadata'][item.key] = item.value
                        
                        # Network interfaces and check for public IPs
                        for iface in inst.network_interfaces or []:
                            interface_info = {
                                'network': iface.network.split('/')[-1] if iface.network else None,
                                'networkIP': iface.network_i_p,
                                'accessConfigs': []
                            }
                            # Check for external/public IPs
                            for ac in iface.access_configs or []:
                                if ac.nat_i_p:
                                    interface_info['accessConfigs'].append({
                                        'type': ac.type_,
                                        'name': ac.name,
                                        'natIP': ac.nat_i_p
                                    })
                            instance_info['networkInterfaces'].append(interface_info)
                        
                        # Service accounts
                        for sa in inst.service_accounts or []:
                            instance_info['serviceAccounts'].append({
                                'email': sa.email,
                                'scopes': list(sa.scopes) if sa.scopes else []
                            })
                            # Track for access analysis
                            self._compute_service_accounts.add(sa.email)
                        
                        # Disk encryption info
                        for disk in inst.disks or []:
                            disk_info = {
                                'source': disk.source.split('/')[-1] if disk.source else None,
                                'boot': disk.boot,
                                'autoDelete': disk.auto_delete
                            }
                            if disk.disk_encryption_key:
                                disk_info['encryption'] = 'CMEK' if disk.disk_encryption_key.kms_key_name else 'GOOGLE_MANAGED'
                            else:
                                disk_info['encryption'] = 'GOOGLE_MANAGED'
                            instance_info['diskEncryption'].append(disk_info)
                        
                        # Shielded instance config
                        if inst.shielded_instance_config:
                            instance_info['shieldedInstanceConfig'] = {
                                'enableSecureBoot': inst.shielded_instance_config.enable_secure_boot,
                                'enableVtpm': inst.shielded_instance_config.enable_vtpm,
                                'enableIntegrityMonitoring': inst.shielded_instance_config.enable_integrity_monitoring
                            }
                        
                        # Confidential instance config
                        if inst.confidential_instance_config:
                            instance_info['confidentialInstanceConfig'] = {
                                'enableConfidentialCompute': inst.confidential_instance_config.enable_confidential_compute
                            }
                        
                        instances.append(instance_info)
            
            results['instances'] = instances
            
            # Networks
            networks = [{
                'name': net.name,
                'autoCreateSubnetworks': net.auto_create_subnetworks,
                'mtu': net.mtu
            } for net in self.networks_client.list(project=self.project_id)]
            results['networks'] = networks
            
        except Exception as e:
            print(f"Error collecting compute resources: {e}")
            
        return results
    
    def collect_networking_resources(self) -> Dict[str, Any]:
        """Collect networking resources"""
        print("\n[Networking] Collecting networking resources...")
        results = {}
        
        try:
            # Firewall rules - the network bouncers
            firewall_rules = [{
                'name': rule.name,
                'direction': rule.direction,
                'priority': rule.priority,
                'sourceRanges': rule.source_ranges,
                'allowed': [{'IPProtocol': a.I_p_protocol, 'ports': a.ports} for a in (rule.allowed or [])],
                'denied': [{'IPProtocol': d.I_p_protocol, 'ports': d.ports} for d in (rule.denied or [])],
                'targetTags': rule.target_tags,
                'sourceTags': rule.source_tags
            } for rule in self.firewalls_client.list(project=self.project_id)]
            results['firewall_rules'] = firewall_rules
            # Subnets
            subnets_client = compute_v1.SubnetworksClient()
            subnets = []
            for region, response in subnets_client.aggregated_list(project=self.project_id):
                if response.subnetworks:
                    subnets.extend([{
                        'name': subnet.name,
                        'network': subnet.network.split('/')[-1] if subnet.network else None,
                        'ipCidrRange': subnet.ip_cidr_range,
                        'region': region.split('/')[-1],
                        'privateIpGoogleAccess': subnet.private_ip_google_access,
                        'enableFlowLogs': subnet.enable_flow_logs
                    } for subnet in response.subnetworks])
            results['subnets'] = subnets
            
            # Routes
            routes_client = compute_v1.RoutesClient()
            routes = [{
                'name': route.name,
                'network': route.network.split('/')[-1] if route.network else None,
                'destRange': route.dest_range,
                'priority': route.priority,
                'nextHopGateway': route.next_hop_gateway.split('/')[-1] if route.next_hop_gateway else None,
                'nextHopIp': route.next_hop_ip
            } for route in routes_client.list(project=self.project_id)]
            results['routes'] = routes
            
            # Load balancers (forwarding rules)
            forwarding_rules_client = compute_v1.ForwardingRulesClient()
            forwarding_rules = []
            for region, response in forwarding_rules_client.aggregated_list(project=self.project_id):
                if response.forwarding_rules:
                    forwarding_rules.extend([{
                        'name': rule.name,
                        'region': region.split('/')[-1] if 'regions/' in region else 'global',
                        'IPAddress': rule.I_p_address,
                        'IPProtocol': rule.I_p_protocol,
                        'portRange': rule.port_range,
                        'loadBalancingScheme': rule.load_balancing_scheme
                    } for rule in response.forwarding_rules])
            results['load_balancers'] = forwarding_rules
            
            # SSL Policies
            ssl_policies_client = compute_v1.SslPoliciesClient()
            ssl_policies = [{
                'name': policy.name,
                'profile': policy.profile,
                'minTlsVersion': policy.min_tls_version,
                'enabledFeatures': policy.enabled_features
            } for policy in ssl_policies_client.list(project=self.project_id)]
            results['ssl_policies'] = ssl_policies
            
            # Cloud Armor Security Policies
            security_policies_client = compute_v1.SecurityPoliciesClient()
            cloud_armor_policies = [{
                'name': policy.name,
                'description': policy.description,
                'rules': [{
                    'priority': rule.priority,
                    'action': rule.action,
                    'match': rule.match.expr.expression if rule.match and rule.match.expr else None
                } for rule in (policy.rules or [])]
            } for policy in security_policies_client.list(project=self.project_id)]
            results['cloud_armor_policies'] = cloud_armor_policies
            
            # VPN Tunnels
            vpn_tunnels_client = compute_v1.VpnTunnelsClient()
            vpn_tunnels = []
            for region, response in vpn_tunnels_client.aggregated_list(project=self.project_id):
                if response.vpn_tunnels:
                    vpn_tunnels.extend([{
                        'name': tunnel.name,
                        'region': region.split('/')[-1],
                        'status': tunnel.status,
                        'peerIp': tunnel.peer_ip
                    } for tunnel in response.vpn_tunnels])
            results['vpn_tunnels'] = vpn_tunnels
            
            # Routers
            routers_client = compute_v1.RoutersClient()
            routers = []
            for region, response in routers_client.aggregated_list(project=self.project_id):
                if response.routers:
                    routers.extend([{
                        'name': router.name,
                        'region': region.split('/')[-1],
                        'network': router.network.split('/')[-1] if router.network else None
                    } for router in response.routers])
            results['routers'] = routers
            
            # Backend Services
            backend_services_client = compute_v1.BackendServicesClient()
            backend_services = [{
                'name': service.name,
                'protocol': service.protocol,
                'port': service.port,
                'portName': service.port_name,
                'timeoutSec': service.timeout_sec,
                'healthChecks': [hc.split('/')[-1] for hc in (service.health_checks or [])]
            } for service in backend_services_client.list(project=self.project_id)]
            results['backend_services'] = backend_services
            
            # Health Checks
            health_checks_client = compute_v1.HealthChecksClient()
            health_checks = [{
                'name': check.name,
                'type': check.type_,
                'checkIntervalSec': check.check_interval_sec,
                'timeoutSec': check.timeout_sec
            } for check in health_checks_client.list(project=self.project_id)]
            results['health_checks'] = health_checks
            
        except Exception as e:
            print(f"Error collecting networking resources: {e}")
            import traceback
            traceback.print_exc()
            
        # Network security analysis
        results['network_security_analysis'] = self._analyze_network_security(results)
            
        return results
    
    def _get_service_by_port(self, port: str) -> str:
        """Map common ports to services"""
        port_map = {
            '22': 'SSH',
            '3389': 'RDP',
            '1433': 'SQL Server',
            '3306': 'MySQL',
            '5432': 'PostgreSQL',
            '27017': 'MongoDB',
            '6379': 'Redis',
            '80': 'HTTP',
            '443': 'HTTPS',
            '8080': 'HTTP-Alt',
            '21': 'FTP',
            '23': 'Telnet',
            '25': 'SMTP',
            '53': 'DNS',
            '110': 'POP3',
            '143': 'IMAP',
            '445': 'SMB',
            '1521': 'Oracle',
            '5984': 'CouchDB',
            '9200': 'Elasticsearch',
            '11211': 'Memcached'
        }
        return port_map.get(port, 'Unknown')
    
    def _analyze_network_security(self, network_data: Dict) -> Dict:
        """Analyze network configuration for security issues"""
        analysis = {
            'summary': {},
            'publicExposure': {
                'publicIPs': [],
                'publicLoadBalancers': [],
                'publicFirewallRules': []
            },
            'recommendations': []
        }
        
        # Count public IPs from instances (already collected)
        public_ip_count = 0
        
        # Analyze load balancers for public exposure
        for lb in network_data.get('load_balancers', []):
            if lb.get('loadBalancingScheme') in ['EXTERNAL', 'EXTERNAL_MANAGED']:
                analysis['publicExposure']['publicLoadBalancers'].append({
                    'name': lb.get('name'),
                    'ipAddress': lb.get('IPAddress'),
                    'region': lb.get('region')
                })
        
        # Summarize firewall analysis
        fw_analysis = network_data.get('firewall_analysis', {})
        if fw_analysis.get('publiclyAccessible'):
            analysis['publicExposure']['publicFirewallRules'] = fw_analysis['publiclyAccessible']
        
        # Add recommendations
        if fw_analysis.get('highRiskRules'):
            analysis['recommendations'].append({
                'severity': 'HIGH',
                'category': 'Network Security',
                'finding': f"Found {len(fw_analysis['highRiskRules'])} firewall rules exposing sensitive services to the internet",
                'recommendation': 'Restrict access to sensitive services using source IP allowlists'
            })
        
        if len(analysis['publicExposure']['publicLoadBalancers']) > 0:
            analysis['recommendations'].append({
                'severity': 'INFO',
                'category': 'Network Security',
                'finding': f"Found {len(analysis['publicExposure']['publicLoadBalancers'])} public-facing load balancers",
                'recommendation': 'Ensure all public endpoints have proper authentication and DDoS protection'
            })
        
        analysis['summary'] = {
            'publicLoadBalancers': len(analysis['publicExposure']['publicLoadBalancers']),
            'highRiskFirewallRules': len(fw_analysis.get('highRiskRules', [])),
            'wideOpenPorts': len(fw_analysis.get('wideOpenPorts', []))
        }
        
        return analysis
    
    def collect_logging_monitoring(self) -> Dict[str, Any]:
        """Collect logging and monitoring configuration"""
        print("\n[Logging/Monitoring] Collecting logging and monitoring config...")
        results = {}
        
        try:
            # Log sinks
            sinks = [{
                'name': sink.name,
                'destination': sink.destination,
                'filter': sink.filter_  # Note: filter_ not filter
            } for sink in self.logging_client.list_sinks()]
            results['log_sinks'] = sinks
            
            # Monitoring alert policies
            monitoring_client = monitoring_v3.AlertPolicyServiceClient(credentials=self.credentials)
            policies = [{
                'name': policy.name,
                'displayName': policy.display_name,
                'enabled': policy.enabled.value
            } for policy in monitoring_client.list_alert_policies(name=f'projects/{self.project_id}')]
            results['alert_policies'] = policies
            
        except Exception as e:
            print(f"Error collecting logging/monitoring: {e}")
            
        return results
    
    def collect_security_services(self) -> Dict[str, Any]:
        """Collect security-related services configuration"""
        print("\n[Security] Collecting security services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            service = discovery.build('serviceusage', 'v1', credentials=self.credentials)
            
            enabled_apis = service.services().list(
                parent=f'projects/{self.project_id}',
                filter='state:ENABLED'
            ).execute()
            
            results['enabled_apis'] = [{
                'name': api.get('name', '').split('/')[-1],
                'state': api.get('state')
            } for api in enabled_apis.get('services', [])]
            
            # KMS configuration
            results['kms_enabled'] = any(api['name'] == 'cloudkms.googleapis.com' 
                                       for api in results['enabled_apis'])
            
        except Exception as e:
            print(f"Error collecting security services: {e}")
            
        return results
    
    def collect_serverless_services(self) -> Dict[str, Any]:
        """Collect serverless services (Cloud Functions, Cloud Run, App Engine)"""
        print("\n[Serverless] Collecting serverless services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Cloud Functions
            try:
                functions_service = discovery.build('cloudfunctions', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1', 'us-west2', 'us-west3', 'us-west4', 
                           'us-east4', 'us-south1', 'northamerica-northeast1', 'northamerica-northeast2']
                
                functions = []
                for location in locations:
                    try:
                        response = functions_service.projects().locations().functions().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'functions' in response:
                            functions.extend([{
                                'name': f.get('name', '').split('/')[-1],
                                'region': location,
                                'runtime': f.get('runtime'),
                                'entryPoint': f.get('entryPoint'),
                                'serviceAccountEmail': f.get('serviceAccountEmail')
                            } for f in response['functions']])
                    except:
                        pass
                results['cloud_functions'] = functions
            except Exception as e:
                if 'not enabled' not in str(e).lower():
                    print(f"Cloud Functions error: {e}")
                results['cloud_functions'] = []
            
            # Cloud Run
            try:
                run_service = discovery.build('run', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1', 'us-east4']
                
                services = []
                for location in locations:
                    try:
                        response = run_service.projects().locations().services().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'items' in response:
                            services.extend([{
                                'name': s.get('metadata', {}).get('name'),
                                'region': location,
                                'managed': s.get('spec', {}).get('template', {}).get('metadata', {}).get('labels', {}).get('run.googleapis.com/execution-environment')
                            } for s in response['items']])
                    except:
                        pass
                results['cloud_run_services'] = services
            except Exception as e:
                if 'not enabled' not in str(e).lower():
                    print(f"Cloud Run error: {e}")
                results['cloud_run_services'] = []
            
            # App Engine
            try:
                appengine_service = discovery.build('appengine', 'v1', credentials=self.credentials)
                
                # Get app info
                app = appengine_service.apps().get(appsId=self.project_id).execute()
                results['app_engine_app'] = {
                    'id': app.get('id'),
                    'locationId': app.get('locationId'),
                    'servingStatus': app.get('servingStatus')
                }
                
                # Get services
                services_response = appengine_service.apps().services().list(
                    appsId=self.project_id
                ).execute()
                results['app_engine_services'] = services_response.get('services', [])
                
                # Get versions
                versions = []
                for service in results['app_engine_services']:
                    versions_response = appengine_service.apps().services().versions().list(
                        appsId=self.project_id,
                        servicesId=service.get('id')
                    ).execute()
                    versions.extend(versions_response.get('versions', []))
                results['app_engine_versions'] = versions
                
            except Exception as e:
                if 'not found' not in str(e).lower():
                    print(f"App Engine error: {e}")
                results['app_engine_app'] = None
                results['app_engine_services'] = []
                results['app_engine_versions'] = []
                
        except Exception as e:
            print(f"Error collecting serverless services: {e}")
            
        return results
    
    def collect_database_services(self) -> Dict[str, Any]:
        """Collect all database services (Spanner, Bigtable, Redis, Firestore, SQL databases)"""
        print("\n[Database] Collecting all database services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Cloud SQL Databases (not just instances)
            try:
                sql_service = discovery.build('sqladmin', 'v1', credentials=self.credentials)
                instances = sql_service.instances().list(project=self.project_id).execute()
                
                databases = []
                if 'items' in instances:
                    for instance in instances['items']:
                        db_response = sql_service.databases().list(
                            project=self.project_id,
                            instance=instance['name']
                        ).execute()
                        for db in db_response.get('items', []):
                            databases.append({
                                'name': db.get('name'),
                                'instance': instance['name'],
                                'charset': db.get('charset'),
                                'collation': db.get('collation')
                            })
                results['sql_databases'] = databases
            except:
                results['sql_databases'] = []
            
            # Cloud Spanner
            try:
                spanner_service = discovery.build('spanner', 'v1', credentials=self.credentials)
                spanner_instances = spanner_service.projects().instances().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                results['spanner_instances'] = [{
                    'name': i.get('name', '').split('/')[-1],
                    'config': i.get('config', '').split('/')[-1],
                    'nodeCount': i.get('nodeCount'),
                    'state': i.get('state')
                } for i in spanner_instances.get('instances', [])]
            except:
                results['spanner_instances'] = []
            
            # Cloud Bigtable
            try:
                bigtable_service = discovery.build('bigtableadmin', 'v2', credentials=self.credentials)
                bigtable_instances = bigtable_service.projects().instances().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                results['bigtable_instances'] = [{
                    'name': i.get('name', '').split('/')[-1],
                    'displayName': i.get('displayName'),
                    'type': i.get('type'),
                    'state': i.get('state')
                } for i in bigtable_instances.get('instances', [])]
            except:
                results['bigtable_instances'] = []
            
            # Redis (Memorystore)
            try:
                redis_service = discovery.build('redis', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1', 'us-east4']
                
                redis_instances = []
                for location in locations:
                    try:
                        response = redis_service.projects().locations().instances().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'instances' in response:
                            redis_instances.extend([{
                                'name': i.get('name', '').split('/')[-1],
                                'tier': i.get('tier'),
                                'memorySizeGb': i.get('memorySizeGb'),
                                'state': i.get('state'),
                                'redisVersion': i.get('redisVersion')
                            } for i in response['instances']])
                    except:
                        pass
                results['redis_instances'] = redis_instances
            except:
                results['redis_instances'] = []
            
            # Firestore
            try:
                firestore_service = discovery.build('firestore', 'v1', credentials=self.credentials)
                firestore_dbs = firestore_service.projects().databases().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                results['firestore_databases'] = [{
                    'name': db.get('name', '').split('/')[-1],
                    'type': db.get('type'),
                    'concurrencyMode': db.get('concurrencyMode'),
                    'locationId': db.get('locationId')
                } for db in firestore_dbs.get('databases', [])]
            except:
                results['firestore_databases'] = []
                
        except Exception as e:
            print(f"Error collecting database services: {e}")
            
        return results
    
    def collect_bigdata_services(self) -> Dict[str, Any]:
        """Collect big data services (BigQuery, Dataflow, Dataproc, Pub/Sub, Composer)"""
        print("\n[BigData] Collecting big data services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Pub/Sub Topics and Subscriptions
            try:
                # Topics
                topics = []
                for topic in self.pubsub_client.list_topics(request={"project": f"projects/{self.project_id}"}):
                    topics.append({
                        'name': topic.name.split('/')[-1],
                        'labels': dict(topic.labels) if topic.labels else {}
                    })
                results['pubsub_topics'] = topics
                
                # Subscriptions
                subscriber_client = pubsub_v1.SubscriberClient()
                subscriptions = []
                for sub in subscriber_client.list_subscriptions(request={"project": f"projects/{self.project_id}"}):
                    subscriptions.append({
                        'name': sub.name.split('/')[-1],
                        'topic': sub.topic.split('/')[-1] if sub.topic else None,
                        'ackDeadlineSeconds': sub.ack_deadline_seconds
                    })
                results['pubsub_subscriptions'] = subscriptions
            except:
                results['pubsub_topics'] = []
                results['pubsub_subscriptions'] = []
            
            # BigQuery
            try:
                bigquery_service = discovery.build('bigquery', 'v2', credentials=self.credentials)
                datasets = bigquery_service.datasets().list(projectId=self.project_id).execute()
                results['bigquery_datasets'] = [{
                    'datasetId': ds.get('datasetReference', {}).get('datasetId'),
                    'location': ds.get('location'),
                    'labels': ds.get('labels', {})
                } for ds in datasets.get('datasets', [])]
            except:
                results['bigquery_datasets'] = []
            
            # Dataflow
            try:
                dataflow_service = discovery.build('dataflow', 'v1b3', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1', 'us-east4']
                
                jobs = []
                for location in locations:
                    try:
                        response = dataflow_service.projects().locations().jobs().list(
                            projectId=self.project_id,
                            location=location
                        ).execute()
                        if 'jobs' in response:
                            jobs.extend([{
                                'name': j.get('name'),
                                'type': j.get('type'),
                                'state': j.get('currentState'),
                                'createTime': j.get('createTime')
                            } for j in response['jobs']])
                    except:
                        pass
                results['dataflow_jobs'] = jobs
            except:
                results['dataflow_jobs'] = []
            
            # Dataproc
            try:
                dataproc_service = discovery.build('dataproc', 'v1', credentials=self.credentials)
                regions = ['us-central1', 'us-east1', 'us-west1']
                
                clusters = []
                for region in regions:
                    try:
                        response = dataproc_service.projects().regions().clusters().list(
                            projectId=self.project_id,
                            region=region
                        ).execute()
                        if 'clusters' in response:
                            clusters.extend([{
                                'clusterName': c.get('clusterName'),
                                'status': c.get('status', {}).get('state'),
                                'region': region
                            } for c in response['clusters']])
                    except:
                        pass
                results['dataproc_clusters'] = clusters
            except:
                results['dataproc_clusters'] = []
            
            # Composer
            try:
                composer_service = discovery.build('composer', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1']
                
                environments = []
                for location in locations:
                    try:
                        response = composer_service.projects().locations().environments().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'environments' in response:
                            environments.extend([{
                                'name': e.get('name', '').split('/')[-1],
                                'state': e.get('state'),
                                'createTime': e.get('createTime')
                            } for e in response['environments']])
                    except:
                        pass
                results['composer_environments'] = environments
            except:
                results['composer_environments'] = []
                
        except Exception as e:
            print(f"Error collecting big data services: {e}")
            
        return results
    
    def collect_security_compliance(self) -> Dict[str, Any]:
        """Collect security and compliance service metadata"""
        print("\n[Security/Compliance] Collecting security and compliance data...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Security Command Center
            try:
                scc_service = discovery.build('securitycenter', 'v1', credentials=self.credentials)
                
                # Sources
                sources = scc_service.organizations().sources().list(
                    parent=f'organizations/{self._get_organization_id()}'
                ).execute()
                results['scc_sources'] = sources.get('sources', [])
                
                # Settings
                try:
                    settings = scc_service.organizations().getOrganizationSettings(
                        name=f'organizations/{self._get_organization_id()}/organizationSettings'
                    ).execute()
                    results['scc_settings'] = settings
                except:
                    results['scc_settings'] = {}
                    
            except:
                results['scc_sources'] = []
                results['scc_settings'] = {}
            
            # VPC Service Controls
            try:
                accesscontext_service = discovery.build('accesscontextmanager', 'v1', credentials=self.credentials)
                perimeters = accesscontext_service.accessPolicies().servicePerimeters().list(
                    parent=f'accessPolicies/{self._get_access_policy_id()}'
                ).execute()
                results['vpc_service_perimeters'] = perimeters.get('servicePerimeters', [])
            except:
                results['vpc_service_perimeters'] = []
            
            # Certificate Authority
            try:
                ca_service = discovery.build('privateca', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1']
                
                ca_pools = []
                for location in locations:
                    try:
                        response = ca_service.projects().locations().caPools().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'caPools' in response:
                            ca_pools.extend(response['caPools'])
                    except:
                        pass
                results['certificate_authority_pools'] = ca_pools
            except:
                results['certificate_authority_pools'] = []
            
            # API Keys
            try:
                apikeys_service = discovery.build('apikeys', 'v2', credentials=self.credentials)
                keys_response = apikeys_service.projects().locations().keys().list(
                    parent=f'projects/{self.project_id}/locations/global'
                ).execute()
                results['api_keys'] = [{
                    'name': k.get('name', '').split('/')[-1],
                    'displayName': k.get('displayName'),
                    'restrictions': k.get('restrictions', {})
                } for k in keys_response.get('keys', [])]
            except:
                results['api_keys'] = []
            
            # Secret Manager - including versions
            try:
                secrets = []
                for secret in self.secrets_client.list_secrets(request={"parent": f"projects/{self.project_id}"}):
                    secret_info = {
                        'name': secret.name.split('/')[-1],
                        'createTime': secret.create_time.isoformat() if secret.create_time else None,
                        'replication': str(secret.replication)
                    }
                    
                    # Get versions count
                    versions = list(self.secrets_client.list_secret_versions(
                        request={"parent": secret.name}
                    ))
                    secret_info['versionCount'] = len(versions)
                    secret_info['latestVersion'] = versions[0].name.split('/')[-1] if versions else None
                    
                    secrets.append(secret_info)
                results['secrets'] = secrets
            except:
                results['secrets'] = []
            
            # Asset Inventory
            try:
                asset_service = discovery.build('cloudasset', 'v1', credentials=self.credentials)
                # Get a snapshot of all resources
                asset_types = [
                    'compute.googleapis.com/Instance',
                    'storage.googleapis.com/Bucket',
                    'iam.googleapis.com/ServiceAccount',
                    'cloudkms.googleapis.com/CryptoKey'
                ]
                
                assets_summary = {}
                for asset_type in asset_types:
                    try:
                        response = asset_service.assets().list(
                            parent=f'projects/{self.project_id}',
                            assetTypes=[asset_type],
                            pageSize=1
                        ).execute()
                        # Just get count for summary
                        assets_summary[asset_type.split('/')[-1]] = len(response.get('assets', []))
                    except:
                        pass
                results['asset_inventory_summary'] = assets_summary
            except:
                results['asset_inventory_summary'] = {}
            
            # Source Repositories
            try:
                source_service = discovery.build('sourcerepo', 'v1', credentials=self.credentials)
                repos = source_service.projects().repos().list(
                    name=f'projects/{self.project_id}'
                ).execute()
                results['source_repositories'] = [{
                    'name': r.get('name', '').split('/')[-1],
                    'size': r.get('size'),
                    'url': r.get('url')
                } for r in repos.get('repos', [])]
            except:
                results['source_repositories'] = []
            
            # Container Image Vulnerabilities
            try:
                container_service = discovery.build('containeranalysis', 'v1', credentials=self.credentials)
                # Get vulnerability occurrences
                vulnerabilities = container_service.projects().occurrences().list(
                    parent=f'projects/{self.project_id}',
                    filter='kind="VULNERABILITY"',
                    pageSize=100
                ).execute()
                
                vuln_summary = {
                    'total': len(vulnerabilities.get('occurrences', [])),
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
                
                for vuln in vulnerabilities.get('occurrences', []):
                    severity = vuln.get('vulnerability', {}).get('severity', 'UNKNOWN')
                    if severity == 'CRITICAL':
                        vuln_summary['critical'] += 1
                    elif severity == 'HIGH':
                        vuln_summary['high'] += 1
                    elif severity == 'MEDIUM':
                        vuln_summary['medium'] += 1
                    elif severity == 'LOW':
                        vuln_summary['low'] += 1
                        
                results['container_vulnerabilities'] = vuln_summary
            except:
                results['container_vulnerabilities'] = {'total': 0}
                
        except Exception as e:
            print(f"Error collecting security/compliance data: {e}")
            
        return results
    
    def collect_aiml_services(self) -> Dict[str, Any]:
        """Collect AI/ML services (Vertex AI, Notebooks)"""
        print("\n[AI/ML] Collecting AI/ML services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Vertex AI Models
            try:
                aiplatform_service = discovery.build('aiplatform', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1']
                
                models = []
                endpoints = []
                
                for location in locations:
                    try:
                        # Models
                        models_response = aiplatform_service.projects().locations().models().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'models' in models_response:
                            models.extend([{
                                'name': m.get('name', '').split('/')[-1],
                                'displayName': m.get('displayName'),
                                'deployedModelCount': len(m.get('deployedModels', []))
                            } for m in models_response['models']])
                        
                        # Endpoints
                        endpoints_response = aiplatform_service.projects().locations().endpoints().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'endpoints' in endpoints_response:
                            endpoints.extend([{
                                'name': e.get('name', '').split('/')[-1],
                                'displayName': e.get('displayName'),
                                'deployedModels': len(e.get('deployedModels', []))
                            } for e in endpoints_response['endpoints']])
                    except:
                        pass
                        
                results['vertex_ai_models'] = models
                results['vertex_ai_endpoints'] = endpoints
            except:
                results['vertex_ai_models'] = []
                results['vertex_ai_endpoints'] = []
            
            # AI Notebooks
            try:
                notebooks_service = discovery.build('notebooks', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1']
                
                notebooks = []
                for location in locations:
                    try:
                        response = notebooks_service.projects().locations().instances().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'instances' in response:
                            notebooks.extend([{
                                'name': n.get('name', '').split('/')[-1],
                                'machineType': n.get('machineType', '').split('/')[-1],
                                'state': n.get('state')
                            } for n in response['instances']])
                    except:
                        pass
                results['ai_notebooks'] = notebooks
            except:
                results['ai_notebooks'] = []
                
        except Exception as e:
            print(f"Error collecting AI/ML services: {e}")
            
        return results
    
    def collect_backup_build_services(self) -> Dict[str, Any]:
        """Collect backup and build services"""
        print("\n[Backup/Build] Collecting backup and build services...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Backup policies and snapshots
            try:
                # Resource policies (backup schedules)
                policies_client = compute_v1.ResourcePoliciesClient()
                policies = []
                for region, response in policies_client.aggregated_list(project=self.project_id):
                    if response.resource_policies:
                        policies.extend([{
                            'name': p.name,
                            'region': region.split('/')[-1],
                            'description': p.description,
                            'snapshotSchedulePolicy': bool(p.snapshot_schedule_policy)
                        } for p in response.resource_policies if p.snapshot_schedule_policy])
                results['backup_policies'] = policies
                
                # Compute snapshots
                snapshots_client = compute_v1.SnapshotsClient()
                snapshots = [{
                    'name': s.name,
                    'sourceDisk': s.source_disk.split('/')[-1] if s.source_disk else None,
                    'diskSizeGb': s.disk_size_gb,
                    'storageLocations': s.storage_locations,
                    'creationTimestamp': s.creation_timestamp
                } for s in snapshots_client.list(project=self.project_id)]
                results['compute_snapshots'] = snapshots
            except:
                results['backup_policies'] = []
                results['compute_snapshots'] = []
            
            # Backup and DR
            try:
                backupdr_service = discovery.build('backupdr', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1']
                
                backup_plans = []
                backups = []
                
                for location in locations:
                    try:
                        # Backup plans
                        plans_response = backupdr_service.projects().locations().backupPlans().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'backupPlans' in plans_response:
                            backup_plans.extend(plans_response['backupPlans'])
                        
                        # Backups
                        backups_response = backupdr_service.projects().locations().backupVaults().dataSources().backups().list(
                            parent=f'projects/{self.project_id}/locations/{location}/backupVaults/-/dataSources/-'
                        ).execute()
                        if 'backups' in backups_response:
                            backups.extend(backups_response['backups'])
                    except:
                        pass
                        
                results['backup_plans'] = backup_plans
                results['backups'] = backups
            except:
                results['backup_plans'] = []
                results['backups'] = []
            
            # Cloud Build
            try:
                cloudbuild_service = discovery.build('cloudbuild', 'v1', credentials=self.credentials)
                
                # Build history
                builds = cloudbuild_service.projects().builds().list(
                    projectId=self.project_id,
                    pageSize=50
                ).execute()
                
                results['cloud_builds'] = [{
                    'id': b.get('id'),
                    'status': b.get('status'),
                    'createTime': b.get('createTime'),
                    'source': b.get('source', {}).get('storageSource', {}).get('bucket') if b.get('source') else None
                } for b in builds.get('builds', [])]
                
                # Build triggers
                triggers = cloudbuild_service.projects().triggers().list(
                    projectId=self.project_id
                ).execute()
                results['build_triggers'] = [{
                    'name': t.get('name'),
                    'description': t.get('description'),
                    'disabled': t.get('disabled', False)
                } for t in triggers.get('triggers', [])]
                
            except:
                results['cloud_builds'] = []
                results['build_triggers'] = []
                
        except Exception as e:
            print(f"Error collecting backup/build services: {e}")
            
        return results
    
    def collect_additional_compute_resources(self) -> Dict[str, Any]:
        """Collect additional compute resources not in main compute collection"""
        print("\n[Compute-Extended] Collecting additional compute resources...")
        results = {}
        
        try:
            # Instance Templates
            templates_client = compute_v1.InstanceTemplatesClient()
            templates = [{
                'name': t.name,
                'description': t.description,
                'machineType': t.properties.machine_type.split('/')[-1] if t.properties and t.properties.machine_type else None
            } for t in templates_client.list(project=self.project_id)]
            results['instance_templates'] = templates
            
            # Managed Instance Groups
            mig_client = compute_v1.InstanceGroupManagersClient()
            migs = []
            for zone, response in mig_client.aggregated_list(project=self.project_id):
                if response.instance_group_managers:
                    migs.extend([{
                        'name': mig.name,
                        'zone': zone.split('/')[-1],
                        'targetSize': mig.target_size,
                        'instanceTemplate': mig.instance_template.split('/')[-1] if mig.instance_template else None
                    } for mig in response.instance_group_managers])
            results['managed_instance_groups'] = migs
            
            # Images
            images_client = compute_v1.ImagesClient()
            images = [{
                'name': img.name,
                'family': img.family,
                'sourceType': img.source_type,
                'diskSizeGb': img.disk_size_gb
            } for img in images_client.list(project=self.project_id)]
            results['custom_images'] = images
            
            # Machine Images
            machine_images_client = compute_v1.MachineImagesClient()
            machine_images = [{
                'name': mi.name,
                'description': mi.description,
                'sourceInstance': mi.source_instance.split('/')[-1] if mi.source_instance else None
            } for mi in machine_images_client.list(project=self.project_id)]
            results['machine_images'] = machine_images
            
            # Zones list
            zones_client = compute_v1.ZonesClient()
            zones = [{
                'name': z.name,
                'region': z.region.split('/')[-1] if z.region else None,
                'status': z.status
            } for z in zones_client.list(project=self.project_id)]
            results['zones'] = zones
            
            # SSL Certificates
            ssl_certs_client = compute_v1.SslCertificatesClient()
            ssl_certs = [{
                'name': cert.name,
                'type': cert.type_,
                'subjectAlternativeNames': cert.subject_alternative_names,
                'expireTime': cert.expire_time
            } for cert in ssl_certs_client.list(project=self.project_id)]
            results['ssl_certificates'] = ssl_certs
            
            # Target HTTPS Proxies
            https_proxies_client = compute_v1.TargetHttpsProxiesClient()
            https_proxies = [{
                'name': proxy.name,
                'urlMap': proxy.url_map.split('/')[-1] if proxy.url_map else None,
                'sslCertificates': [c.split('/')[-1] for c in proxy.ssl_certificates] if proxy.ssl_certificates else []
            } for proxy in https_proxies_client.list(project=self.project_id)]
            results['target_https_proxies'] = https_proxies
            
            # URL Maps
            url_maps_client = compute_v1.UrlMapsClient()
            url_maps = [{
                'name': um.name,
                'defaultService': um.default_service.split('/')[-1] if um.default_service else None
            } for um in url_maps_client.list(project=self.project_id)]
            results['url_maps'] = url_maps
            
            # OS Patching
            from googleapiclient import discovery
            
            try:
                osconfig_service = discovery.build('osconfig', 'v1', credentials=self.credentials)
                
                # Patch Jobs
                patch_jobs = osconfig_service.projects().patchJobs().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                results['os_patch_jobs'] = [{
                    'name': job.get('name', '').split('/')[-1],
                    'state': job.get('state'),
                    'patchConfig': job.get('patchConfig', {})
                } for job in patch_jobs.get('patchJobs', [])]
                
                # Patch Deployments
                patch_deployments = osconfig_service.projects().patchDeployments().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                results['os_patch_deployments'] = [{
                    'name': dep.get('name', '').split('/')[-1],
                    'description': dep.get('description'),
                    'state': dep.get('state')
                } for dep in patch_deployments.get('patchDeployments', [])]
                
                # OS Inventory
                # Note: Inventory is per-instance, so we sample a few instances
                inventory_summary = {'instances_with_inventory': 0, 'total_instances_checked': 0}
                results['os_inventory_summary'] = inventory_summary
                
            except Exception as e:
                if 'not enabled' not in str(e).lower():
                    print(f"OS Config error: {e}")
                results['os_patch_jobs'] = []
                results['os_patch_deployments'] = []
                results['os_inventory_summary'] = {}
            
            # Deployment Manager
            try:
                deployment_service = discovery.build('deploymentmanager', 'v2', credentials=self.credentials)
                deployments = deployment_service.deployments().list(
                    project=self.project_id
                ).execute()
                results['deployment_manager'] = [{
                    'name': d.get('name'),
                    'insertTime': d.get('insertTime'),
                    'manifest': d.get('manifest', '').split('/')[-1] if d.get('manifest') else None
                } for d in deployments.get('deployments', [])]
            except:
                results['deployment_manager'] = []
            
        except Exception as e:
            print(f"Error collecting additional compute resources: {e}")
            
        return results
    
    def collect_iam_extended(self) -> Dict[str, Any]:
        """Collect extended IAM and identity resources"""
        print("\n[IAM-Extended] Collecting extended IAM resources...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Custom Roles
            iam_service = discovery.build('iam', 'v1', credentials=self.credentials)
            custom_roles = iam_service.projects().roles().list(
                parent=f'projects/{self.project_id}'
            ).execute()
            results['custom_roles'] = [{
                'name': r.get('name', '').split('/')[-1],
                'title': r.get('title'),
                'description': r.get('description'),
                'stage': r.get('stage')
            } for r in custom_roles.get('roles', [])]
            
            # Workload Identity Pools
            try:
                wip_response = iam_service.projects().locations().workloadIdentityPools().list(
                    parent=f'projects/{self.project_id}/locations/global'
                ).execute()
                results['workload_identity_pools'] = wip_response.get('workloadIdentityPools', [])
            except:
                results['workload_identity_pools'] = []
            
            # IAM Recommender
            try:
                recommender_service = discovery.build('recommender', 'v1', credentials=self.credentials)
                recommendations = recommender_service.projects().locations().recommenders().recommendations().list(
                    parent=f'projects/{self.project_id}/locations/global/recommenders/google.iam.policy.Recommender'
                ).execute()
                results['iam_recommendations'] = [{
                    'name': r.get('name', '').split('/')[-1],
                    'description': r.get('description'),
                    'priority': r.get('priority'),
                    'primaryImpact': r.get('primaryImpact', {}).get('category')
                } for r in recommendations.get('recommendations', [])]
            except:
                results['iam_recommendations'] = []
            
            # Organization Policies (if accessible)
            try:
                org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
                org_policies = org_service.projects().listAvailableOrgPolicyConstraints(
                    resource=f'projects/{self.project_id}',
                    body={}
                ).execute()
                results['available_org_policy_constraints'] = org_policies.get('constraints', [])
            except:
                results['available_org_policy_constraints'] = []
                
        except Exception as e:
            print(f"Error collecting extended IAM resources: {e}")
            
        return results
    
    def collect_monitoring_extended(self) -> Dict[str, Any]:
        """Collect extended monitoring and logging resources"""
        print("\n[Monitoring-Extended] Collecting extended monitoring resources...")
        results = {}
        
        try:
            from googleapiclient import discovery
            
            # Log Metrics
            log_metrics = []
            for metric in self.logging_client.list_metrics():
                log_metrics.append({
                    'name': metric.name,
                    'description': metric.description,
                    'filter': metric.filter_
                })
            results['log_metrics'] = log_metrics
            
            # Uptime Checks
            uptime_client = monitoring_v3.UptimeCheckServiceClient(credentials=self.credentials)
            uptime_checks = [{
                'name': check.name,
                'displayName': check.display_name,
                'monitoredResource': check.monitored_resource.type if check.monitored_resource else None,
                'period': check.period.seconds if check.period else None
            } for check in uptime_client.list_uptime_check_configs(parent=f'projects/{self.project_id}')]
            results['uptime_checks'] = uptime_checks
            
            # Monitoring Dashboards
            try:
                # Try the newer client name first
                from google.cloud.monitoring_dashboard_v1 import DashboardsServiceClient
                dashboard_client = DashboardsServiceClient(credentials=self.credentials)
                dashboards = [{
                    'name': dash.name,
                    'displayName': dash.display_name
                } for dash in dashboard_client.list_dashboards(parent=f'projects/{self.project_id}')]
                results['monitoring_dashboards'] = dashboards
            except (ImportError, AttributeError):
                # Fallback to using discovery API
                try:
                    monitoring_service = discovery.build('monitoring', 'v3', credentials=self.credentials)
                    dashboards_response = monitoring_service.projects().dashboards().list(
                        parent=f'projects/{self.project_id}'
                    ).execute()
                    results['monitoring_dashboards'] = [{
                        'name': d.get('name', ''),
                        'displayName': d.get('displayName', '')
                    } for d in dashboards_response.get('dashboards', [])]
                except:
                    results['monitoring_dashboards'] = []
            
            # Audit Log Configs from IAM Policy
            try:
                crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
                policy = crm_service.projects().getIamPolicy(
                    resource=f'projects/{self.project_id}'
                ).execute()
                
                audit_configs = policy.get('auditConfigs', [])
                results['audit_log_configs'] = audit_configs
            except:
                results['audit_log_configs'] = []
            
            # List available logs
            try:
                logs_list = []
                for log in self.logging_client.list_logs():
                    logs_list.append(log)
                results['available_logs'] = logs_list[:50]  # Limit to first 50
            except:
                results['available_logs'] = []
                
        except Exception as e:
            print(f"Error collecting extended monitoring resources: {e}")
            
        return results
    
    def collect_detailed_encryption_assessment(self) -> Dict[str, Any]:
        """Perform detailed encryption assessment across all services"""
        print("\n[Encryption] Checking encryption coverage...")
        assessment = {
            'assessment_timestamp': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'total_resources_checked': 0,
                'cmek_enabled': 0,
                'google_managed': 0,
                'unencrypted': 0
            },
            'by_service': {}
        }
        
        try:
            # Storage encryption summary
            storage_summary = {
                'buckets_total': 0,
                'buckets_cmek': 0,
                'buckets_google_managed': 0
            }
            
            for bucket in self.storage_client.list_buckets():
                storage_summary['buckets_total'] += 1
                assessment['summary']['total_resources_checked'] += 1
                
                if bucket.default_kms_key_name:
                    storage_summary['buckets_cmek'] += 1
                    assessment['summary']['cmek_enabled'] += 1
                else:
                    storage_summary['buckets_google_managed'] += 1
                    assessment['summary']['google_managed'] += 1
                    
            assessment['by_service']['storage'] = storage_summary
            
            # Compute disk encryption summary
            compute_summary = {
                'disks_total': 0,
                'disks_cmek': 0,
                'disks_google_managed': 0
            }
            
            for zone, response in self.disks_client.aggregated_list(project=self.project_id):
                if response.disks:
                    for disk in response.disks:
                        compute_summary['disks_total'] += 1
                        assessment['summary']['total_resources_checked'] += 1
                        
                        if disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name:
                            compute_summary['disks_cmek'] += 1
                            assessment['summary']['cmek_enabled'] += 1
                        else:
                            compute_summary['disks_google_managed'] += 1
                            assessment['summary']['google_managed'] += 1
                            
            assessment['by_service']['compute'] = compute_summary
            
            # SQL encryption summary
            from googleapiclient import discovery
            sql_service = discovery.build('sqladmin', 'v1', credentials=self.credentials)
            
            sql_summary = {
                'instances_total': 0,
                'instances_cmek': 0,
                'instances_google_managed': 0
            }
            
            try:
                instances = sql_service.instances().list(project=self.project_id).execute()
                for instance in instances.get('items', []):
                    sql_summary['instances_total'] += 1
                    assessment['summary']['total_resources_checked'] += 1
                    
                    disk_config = instance.get('diskEncryptionConfiguration', {})
                    if disk_config.get('kmsKeyName'):
                        sql_summary['instances_cmek'] += 1
                        assessment['summary']['cmek_enabled'] += 1
                    else:
                        sql_summary['instances_google_managed'] += 1
                        assessment['summary']['google_managed'] += 1
            except:
                pass
                
            assessment['by_service']['sql'] = sql_summary
            
            # KMS usage assessment
            kms_summary = {
                'key_rings': 0,
                'crypto_keys': 0,
                'keys_with_rotation': 0
            }
            
            try:
                locations = ['global', 'us-central1', 'us-east1', 'us-west1']
                for location in locations:
                    parent = f"projects/{self.project_id}/locations/{location}"
                    
                    # List key rings
                    for key_ring in self.kms_client.list_key_rings(request={"parent": parent}):
                        kms_summary['key_rings'] += 1
                        
                        # List crypto keys
                        for crypto_key in self.kms_client.list_crypto_keys(request={"parent": key_ring.name}):
                            kms_summary['crypto_keys'] += 1
                            
                            # Check rotation period
                            if hasattr(crypto_key, 'rotation_period') and crypto_key.rotation_period:
                                kms_summary['keys_with_rotation'] += 1
            except:
                pass
                
            assessment['by_service']['kms'] = kms_summary
            
            # Organization policy assessment
            org_policy_summary = {
                'encryption_policies_found': False,
                'compute_requireOsLogin': False,
                'compute_disableSerialPortAccess': False,
                'storage_uniformBucketLevelAccess': False
            }
            
            try:
                crm_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
                
                # Check for specific security policies
                constraints_to_check = [
                    'compute.requireOsLogin',
                    'compute.disableSerialPortAccess',
                    'storage.uniformBucketLevelAccess'
                ]
                
                for constraint in constraints_to_check:
                    try:
                        policy = crm_service.projects().getEffectiveOrgPolicy(
                            resource=f'projects/{self.project_id}',
                            body={'constraint': f'constraints/{constraint}'}
                        ).execute()
                        
                        if policy.get('booleanPolicy', {}).get('enforced'):
                            org_policy_summary[constraint.replace('.', '_')] = True
                            org_policy_summary['encryption_policies_found'] = True
                    except:
                        pass
            except:
                pass
                
            assessment['organization_policies'] = org_policy_summary
            
            # Encryption recommendations
            recommendations = []
            
            if storage_summary['buckets_google_managed'] > 0:
                recommendations.append({
                    'service': 'Cloud Storage',
                    'finding': f"{storage_summary['buckets_google_managed']} buckets using Google-managed encryption",
                    'recommendation': 'Consider enabling CMEK for sensitive data buckets',
                    'severity': 'MEDIUM'
                })
                
            if compute_summary['disks_google_managed'] > 0:
                recommendations.append({
                    'service': 'Compute Engine',
                    'finding': f"{compute_summary['disks_google_managed']} disks using Google-managed encryption",
                    'recommendation': 'Consider enabling CMEK for sensitive workload disks',
                    'severity': 'MEDIUM'
                })
                
            if kms_summary['crypto_keys'] > 0 and kms_summary['keys_with_rotation'] < kms_summary['crypto_keys']:
                recommendations.append({
                    'service': 'Cloud KMS',
                    'finding': f"Only {kms_summary['keys_with_rotation']} of {kms_summary['crypto_keys']} keys have rotation enabled",
                    'recommendation': 'Enable automatic rotation for all encryption keys',
                    'severity': 'HIGH'
                })
                
            if not org_policy_summary['encryption_policies_found']:
                recommendations.append({
                    'service': 'Organization Policies',
                    'finding': 'No organization-level encryption policies enforced',
                    'recommendation': 'Implement organization policies to enforce encryption requirements',
                    'severity': 'HIGH'
                })
                
            assessment['recommendations'] = recommendations
            
        except Exception as e:
            print(f"Error in encryption assessment: {e}")
            assessment['error'] = str(e)
            
        return assessment
    
    def _get_organization_id(self) -> str:
        """Get organization ID for the project"""
        try:
            from googleapiclient import discovery
            crm_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            project = crm_service.projects().get(projectId=self.project_id).execute()
            if 'parent' in project and project['parent'].get('type') == 'organization':
                return project['parent']['id']
        except:
            pass
        return 'unknown'
    
    def _get_access_policy_id(self) -> str:
        """Get access policy ID for VPC Service Controls"""
        # This would need to be implemented based on organization setup
        return 'unknown'
    
    def collect_container_services(self) -> Dict[str, Any]:
        """Collect container-related services including GKE with encryption details"""
        print("\n[Containers] Collecting container services...")
        results = {}
        
        try:
            # GKE Clusters with detailed encryption info
            clusters = []
            zones = ['us-central1-a', 'us-central1-b', 'us-central1-c', 'us-east1-b', 'us-east1-c', 'us-east1-d']
            
            for zone in zones:
                try:
                    cluster_list = self.container_client.list_clusters(
                        parent=f'projects/{self.project_id}/locations/{zone}'
                    )
                    for cluster in cluster_list.clusters:
                        cluster_info = {
                            'name': cluster.name,
                            'location': zone,
                            'status': cluster.status.name if cluster.status else 'UNKNOWN',
                            'currentMasterVersion': cluster.current_master_version,
                            'currentNodeVersion': cluster.current_node_version,
                            'nodeCount': cluster.current_node_count,
                            # Encryption details
                            'databaseEncryption': {
                                'state': cluster.database_encryption.state.name if cluster.database_encryption else 'DECRYPTED',
                                'keyName': 'CMEK' if cluster.database_encryption and cluster.database_encryption.key_name else 'GOOGLE_MANAGED'
                            },
                            'bootDiskKmsKey': 'CONFIGURED' if hasattr(cluster, 'node_config') and 
                                             hasattr(cluster.node_config, 'boot_disk_kms_key') and 
                                             cluster.node_config.boot_disk_kms_key else 'GOOGLE_MANAGED'
                        }
                        clusters.append(cluster_info)
                except:
                    pass
                    
            results['gke_clusters'] = clusters
            
            # Container Registry / Artifact Registry
            from googleapiclient import discovery
            
            try:
                # Artifact Registry repositories
                artifactregistry_service = discovery.build('artifactregistry', 'v1', credentials=self.credentials)
                locations = ['us-central1', 'us-east1', 'us-west1', 'us']
                
                repositories = []
                for location in locations:
                    try:
                        repos_response = artifactregistry_service.projects().locations().repositories().list(
                            parent=f'projects/{self.project_id}/locations/{location}'
                        ).execute()
                        if 'repositories' in repos_response:
                            repositories.extend([{
                                'name': r.get('name', '').split('/')[-1],
                                'format': r.get('format'),
                                'kmsKeyName': 'CMEK' if r.get('kmsKeyName') else 'GOOGLE_MANAGED'
                            } for r in repos_response['repositories']])
                    except:
                        pass
                results['artifact_repositories'] = repositories
            except:
                results['artifact_repositories'] = []
                
            # Container Registry images
            try:
                # Get images from gcr.io
                container_service = discovery.build('containeranalysis', 'v1', credentials=self.credentials)
                gcr_images = container_service.projects().occurrences().list(
                    parent=f'projects/{self.project_id}',
                    filter='kind="IMAGE"',
                    pageSize=100
                ).execute()
                
                results['container_images_count'] = len(gcr_images.get('occurrences', []))
            except:
                results['container_images_count'] = 0
                
        except Exception as e:
            print(f"Error collecting container services: {e}")
            
        return results
    
    def _collect_additional_resources(self):
        """Collect additional resources that aren't in the parallel batch"""
        print("\n[Additional] Collecting remaining resources...")
        
        # Encryption summary
        self.save_json('security', 'encryption_summary', {
            'assessment_type': 'encryption_configuration',
            'assessment_date': datetime.now(timezone.utc).isoformat(),
            'note': 'Python collector - encryption assessment without key exposure',
            'kms_apis_enabled': self._check_api_enabled('cloudkms.googleapis.com')
        })
        
        # MFA summary
        print("\n[Security] Generating MFA assessment summary...")
        try:
            # Load the MFA policies data we just collected
            mfa_file = Path(self.output_dir) / 'security' / 'mfa_policies.json'
            if mfa_file.exists():
                with open(mfa_file, 'r') as f:
                    mfa_data = json.load(f)
                
                # Create MFA summary
                mfa_summary = {
                    'assessment_type': 'mfa_enforcement',
                    'assessment_date': datetime.now(timezone.utc).isoformat(),
                    'mfa_compliance_score': mfa_data.get('mfa_compliance_score', 0),
                    'high_risk_findings': len([f for f in mfa_data.get('findings', []) if f.get('severity') == 'HIGH']),
                    'total_high_privilege_users': sum(len(acc['users']) for acc in mfa_data.get('high_privilege_accounts', [])),
                    'mfa_enforcement_methods': {
                        'organization_policies': mfa_data.get('mfa_enforcement', {}).get('organization_level', False),
                        'iam_conditions': len(mfa_data.get('mfa_enforcement', {}).get('conditional_access', [])) > 0,
                        'identity_aware_proxy': mfa_data.get('mfa_enforcement', {}).get('identity_aware_proxy', False)
                    },
                    'key_recommendations': [r['recommendation'] for r in mfa_data.get('recommendations', []) if r.get('priority') == 'HIGH']
                }
                
                self.save_json('security', 'mfa_summary', mfa_summary)
        except Exception as e:
            print(f"Note: Could not create MFA summary: {e}")
        
        # Organization policies
        try:
            from googleapiclient import discovery
            org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            # Try to get org policies
            try:
                org_response = org_service.organizations().search().execute()
                if org_response.get('organizations'):
                    org_id = org_response['organizations'][0]['name'].split('/')[-1]
                    self.save_json('iam', 'organizations', org_response['organizations'])
            except:
                self.save_json('iam', 'organizations', [])
                
        except Exception as e:
            print(f"Note: Could not collect organization data: {e}")
    
    def _check_api_enabled(self, api_name: str) -> bool:
        """Check if a specific API is enabled"""
        try:
            from googleapiclient import discovery
            service = discovery.build('serviceusage', 'v1', credentials=self.credentials)
            
            response = service.services().get(
                name=f'projects/{self.project_id}/services/{api_name}'
            ).execute()
            
            return response.get('state') == 'ENABLED'
        except:
            return False
    
    def collect_all_resources_parallel(self):
        """Collect all resources in parallel for maximum speed"""
        print(f"\n{'='*50}")
        print(f"FedRAMP 20x GCP Data Collection (Python Fast Mode)")
        print(f"Project: {self.project_id}")
        print(f"Output: {self.output_dir}")
        print(f"{'='*50}")
        
        # Define collection tasks
        tasks = [
            # Core infrastructure
            ('storage', 'all_buckets_encryption', self.collect_storage_encryption),
            ('compute', 'all_disks_encryption', self.collect_compute_disk_encryption),
            ('database', 'all_sql_encryption', self.collect_sql_encryption),
            
            # IAM and access
            ('iam', 'iam_data', self.collect_iam_data),
            ('iam', 'iam_extended', self.collect_iam_extended),
            
            # Compute resources
            ('compute', 'compute_resources', self.collect_compute_resources),
            ('compute', 'compute_extended', self.collect_additional_compute_resources),
            
            # Networking resources
            ('networking', 'networking_resources', self.collect_networking_resources),
            
            # Logging and monitoring
            ('monitoring', 'logging_monitoring', self.collect_logging_monitoring),
            ('monitoring', 'monitoring_extended', self.collect_monitoring_extended),
            
            # Security services
            ('security', 'security_services', self.collect_security_services),
            ('security', 'security_compliance', self.collect_security_compliance),
            
            # Serverless services
            ('compute', 'serverless_services', self.collect_serverless_services),
            
            # Database services (extended)
            ('database', 'database_services', self.collect_database_services),
            
            # Big data services
            ('bigdata', 'bigdata_services', self.collect_bigdata_services),
            
            # AI/ML services
            ('aiml', 'aiml_services', self.collect_aiml_services),
            
            # Backup and build services
            ('backup', 'backup_build_services', self.collect_backup_build_services),
            
            # Container services with encryption details
            ('containers', 'container_services', self.collect_container_services),
            
            # Encryption assessment
            ('security', 'encryption_assessment', self.collect_detailed_encryption_assessment),
            
            # Additional FedRAMP collections
            ('audit', 'audit_log_configuration', self.collect_audit_log_details),
            ('compliance', 'organization_constraints', self.collect_org_constraints),
            ('networking', 'vpc_flow_logs', self.collect_network_flow_data),
            ('compliance', 'data_residency', self.collect_data_residency),
            ('security', 'api_security', self.collect_api_security),
            ('security', 'binary_authorization', self.collect_binary_authorization),
            ('security', 'cloud_armor_waf', self.collect_waf_configurations),
            ('identity', 'workload_identity', self.collect_identity_federation),
            ('kms', 'key_usage_audit', self.collect_key_usage_audit),
            ('networking', 'network_endpoints', self.collect_network_endpoints),
            ('compute', 'os_compliance', self.collect_os_compliance),
            ('audit', 'access_approval', self.collect_access_approval),
            ('iam', 'resource_hierarchy', self.collect_resource_hierarchy),
            ('networking', 'shared_vpc', self.collect_vpc_sharing),
            ('compliance', 'essential_contacts', self.collect_essential_contacts),
            ('security', 'mfa_policies', self.collect_mfa_policies),
        ]
        
        # Execute all collections in parallel with more workers for better performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_task = {
                executor.submit(task[2]): task 
                for task in tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_task):
                category, filename, _ = future_to_task[future]
                try:
                    result = future.result()
                    self.save_json(category, filename, result)
                except Exception as e:
                    print(f"Error in {category}/{filename}: {e}")
                    self.save_json(category, filename, {"error": str(e)})
        
        # Collect additional data that wasn't in parallel tasks
        self._collect_additional_resources()
        
        # Create metadata
        metadata = {
            'collection_timestamp': datetime.now(timezone.utc).isoformat(),
            'project_id': self.project_id,
            'collector_version': '3.4.0-python',
            'collection_mode': 'full',
            'note': 'Python collector for pilot-era FedRAMP 20x GCP evidence collection'
        }
        self.save_json('', 'metadata', metadata)
        
        print(f"\nCollection complete. Output saved to: {self.output_dir}")
        
        # Create tar.gz archive
        import tarfile
        archive_name = f"{self.output_dir}.tar.gz"
        with tarfile.open(archive_name, "w:gz") as tar:
            tar.add(self.output_dir, arcname=os.path.basename(self.output_dir))
        print(f"Archive created: {archive_name}")


    def collect_audit_log_details(self) -> Dict[str, Any]:
        """Collect detailed audit log configurations and retention"""
        print("\n[Audit] Collecting detailed audit log configurations...")
        audit_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'log_sinks': [],
            'log_metrics': [],
            'audit_configs': [],
            'retention_policies': {},
            'excluded_logs': []
        }
        
        try:
            # Enhanced log sink collection with destinations
            for sink in self.logging_client.list_sinks():
                sink_info = {
                    'name': sink.name,
                    'destination': sink.destination,
                    'filter': sink.filter_,
                    'description': sink.description if hasattr(sink, 'description') else None,
                    'disabled': sink.disabled,
                    'exclusions': [],
                    'includeChildren': sink.include_children,
                    'createTime': sink.create_time.isoformat() if sink.create_time else None,
                    'updateTime': sink.update_time.isoformat() if sink.update_time else None
                }
                
                # Check destination type
                if 'storage.googleapis.com' in sink.destination:
                    sink_info['destinationType'] = 'storage'
                elif 'bigquery.googleapis.com' in sink.destination:
                    sink_info['destinationType'] = 'bigquery'
                elif 'pubsub.googleapis.com' in sink.destination:
                    sink_info['destinationType'] = 'pubsub'
                else:
                    sink_info['destinationType'] = 'other'
                
                # Get exclusions
                for exclusion in sink.exclusions or []:
                    sink_info['exclusions'].append({
                        'name': exclusion.name,
                        'filter': exclusion.filter,
                        'disabled': exclusion.disabled
                    })
                
                audit_data['log_sinks'].append(sink_info)
            
            # Get detailed log metrics
            for metric in self.logging_client.list_metrics():
                audit_data['log_metrics'].append({
                    'name': metric.name,
                    'description': metric.description,
                    'filter': metric.filter_,
                    'valueExtractor': metric.value_extractor,
                    'metricDescriptor': {
                        'metricKind': metric.metric_descriptor.metric_kind.name if metric.metric_descriptor else None,
                        'valueType': metric.metric_descriptor.value_type.name if metric.metric_descriptor else None
                    }
                })
            
            # Get audit configurations from IAM policy
            from googleapiclient import discovery
            crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            
            try:
                policy = crm_service.projects().getIamPolicy(
                    resource=f'projects/{self.project_id}',
                    body={'options': {'requestedPolicyVersion': 3}}
                ).execute()
                
                audit_data['audit_configs'] = policy.get('auditConfigs', [])
            except:
                pass
            
            # Get log retention policies
            try:
                # Check for organization-level retention
                org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
                project = org_service.projects().get(projectId=self.project_id).execute()
                
                if 'parent' in project:
                    audit_data['retention_policies']['organizationLevel'] = True
                else:
                    audit_data['retention_policies']['organizationLevel'] = False
            except:
                pass
            
            # Analyze excluded logs
            audit_data['excluded_logs'] = self._analyze_excluded_logs(audit_data['log_sinks'])
            
        except Exception as e:
            print(f"Error collecting audit log details: {e}")
            audit_data['error'] = str(e)
        
        return audit_data
    
    def collect_org_constraints(self) -> Dict[str, Any]:
        """Collect all organization policy constraints"""
        print("\n[Compliance] Collecting organization constraints and policies...")
        constraints_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'enforced_constraints': [],
            'available_constraints': [],
            'security_constraints': {},
            'compliance_score': 0
        }
        
        try:
            from googleapiclient import discovery
            org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            # Key security constraints to check
            security_constraints = [
                'compute.disableGuestAttributesAccess',
                'compute.disableInternetNetworkEndpointGroup',
                'compute.disableNestedVirtualization',
                'compute.disableSerialPortLogging',
                'compute.requireShieldedVm',
                'compute.vmExternalIpAccess',
                'compute.vmCanIpForward',
                'compute.restrictXpnProjectLienRemoval',
                'compute.disableVpcExternalIpv6',
                'compute.skipDefaultNetworkCreation',
                'iam.disableServiceAccountKeyCreation',
                'iam.disableServiceAccountCreation',
                'iam.allowedPolicyMemberDomains',
                'iam.disableServiceAccountKeyUpload',
                'iam.automaticIamGrantsForDefaultServiceAccounts',
                'sql.restrictPublicIp',
                'sql.restrictAuthorizedNetworks',
                'storage.publicAccessPrevention',
                'storage.uniformBucketLevelAccess',
                'storage.retentionPolicySeconds'
            ]
            
            # Check each constraint
            enforced_count = 0
            for constraint in security_constraints:
                try:
                    response = org_service.projects().getEffectiveOrgPolicy(
                        resource=f'projects/{self.project_id}',
                        body={'constraint': f'constraints/{constraint}'}
                    ).execute()
                    
                    constraint_info = {
                        'constraint': constraint,
                        'enforced': False,
                        'details': response
                    }
                    
                    # Check if constraint is enforced
                    if 'booleanPolicy' in response and response['booleanPolicy'].get('enforced'):
                        constraint_info['enforced'] = True
                        enforced_count += 1
                    elif 'listPolicy' in response:
                        if 'deniedValues' in response['listPolicy'] or 'allowedValues' in response['listPolicy']:
                            constraint_info['enforced'] = True
                            enforced_count += 1
                    
                    constraints_data['security_constraints'][constraint] = constraint_info
                    
                except Exception as e:
                    if 'does not exist' not in str(e):
                        constraints_data['security_constraints'][constraint] = {
                            'constraint': constraint,
                            'enforced': False,
                            'error': str(e)
                        }
            
            # Calculate compliance score
            if len(security_constraints) > 0:
                constraints_data['compliance_score'] = (enforced_count / len(security_constraints)) * 100
            
            # Get all available constraints
            try:
                available = org_service.projects().listAvailableOrgPolicyConstraints(
                    resource=f'projects/{self.project_id}',
                    body={}
                ).execute()
                constraints_data['available_constraints'] = [
                    c.get('name') for c in available.get('constraints', [])
                ]
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting organization constraints: {e}")
            constraints_data['error'] = str(e)
        
        return constraints_data
    
    def collect_network_flow_data(self) -> Dict[str, Any]:
        """Collect VPC flow logs and NAT configurations"""
        print("\n[Networking] Collecting VPC flow logs and NAT configurations...")
        flow_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'flow_logs_enabled': [],
            'flow_logs_disabled': [],
            'cloud_nat': [],
            'private_google_access': [],
            'private_service_connect': []
        }
        
        try:
            # Check flow logs for each subnet
            subnets_client = compute_v1.SubnetworksClient()
            
            for region, response in subnets_client.aggregated_list(project=self.project_id):
                if response.subnetworks:
                    for subnet in response.subnetworks:
                        subnet_info = {
                            'name': subnet.name,
                            'region': region.split('/')[-1],
                            'network': subnet.network.split('/')[-1] if subnet.network else None,
                            'enableFlowLogs': subnet.enable_flow_logs,
                            'privateIpGoogleAccess': subnet.private_ip_google_access
                        }
                        
                        if subnet.enable_flow_logs:
                            # Get flow log config details
                            if hasattr(subnet, 'log_config') and subnet.log_config:
                                subnet_info['flowLogConfig'] = {
                                    'aggregationInterval': subnet.log_config.aggregation_interval,
                                    'flowSampling': subnet.log_config.flow_sampling,
                                    'metadata': subnet.log_config.metadata
                                }
                            flow_data['flow_logs_enabled'].append(subnet_info)
                        else:
                            flow_data['flow_logs_disabled'].append(subnet_info)
                        
                        # Track private Google access
                        if subnet.private_ip_google_access:
                            flow_data['private_google_access'].append({
                                'subnet': subnet.name,
                                'region': region.split('/')[-1]
                            })
            
            # Get Cloud NAT gateways
            try:
                routers_client = compute_v1.RoutersClient()
                
                for region, response in routers_client.aggregated_list(project=self.project_id):
                    if response.routers:
                        for router in response.routers:
                            if hasattr(router, 'nats') and router.nats:
                                for nat in router.nats:
                                    flow_data['cloud_nat'].append({
                                        'name': nat.name,
                                        'router': router.name,
                                        'region': region.split('/')[-1],
                                        'natIpAllocateOption': nat.nat_ip_allocate_option,
                                        'sourceSubnetworkIpRangesToNat': nat.source_subnetwork_ip_ranges_to_nat,
                                        'enableEndpointIndependentMapping': nat.enable_endpoint_independent_mapping,
                                        'logConfig': {
                                            'enable': nat.log_config.enable if nat.log_config else False,
                                            'filter': nat.log_config.filter if nat.log_config else None
                                        }
                                    })
            except:
                pass
            
            # Get Private Service Connect endpoints
            try:
                from googleapiclient import discovery
                compute_service = discovery.build('compute', 'v1', credentials=self.credentials)
                
                # Get PSC endpoints
                for region in ['us-central1', 'us-east1', 'us-west1', 'us-east4']:
                    try:
                        endpoints = compute_service.forwardingRules().list(
                            project=self.project_id,
                            region=region
                        ).execute()
                        
                        for endpoint in endpoints.get('items', []):
                            if endpoint.get('pscConnectionId'):
                                flow_data['private_service_connect'].append({
                                    'name': endpoint.get('name'),
                                    'region': region,
                                    'pscConnectionId': endpoint.get('pscConnectionId'),
                                    'network': endpoint.get('network', '').split('/')[-1]
                                })
                    except:
                        pass
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting network flow data: {e}")
            flow_data['error'] = str(e)
        
        return flow_data
    
    def collect_data_residency(self) -> Dict[str, Any]:
        """Collect resource locations for data residency compliance"""
        print("\n[Compliance] Collecting data residency information...")
        residency_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'resource_locations': {},
            'multi_region_resources': [],
            'cross_region_replications': [],
            'location_distribution': {}
        }
        
        try:
            # Collect locations by resource type
            location_counts = {}
            
            # Storage bucket locations
            bucket_locations = []
            for bucket in self.storage_client.list_buckets():
                location = bucket.location.lower()
                bucket_locations.append({
                    'resource': f'bucket/{bucket.name}',
                    'location': location,
                    'type': 'storage'
                })
                location_counts[location] = location_counts.get(location, 0) + 1
                
                # Check for multi-region
                if location in ['us', 'eu', 'asia']:
                    residency_data['multi_region_resources'].append({
                        'resource': f'bucket/{bucket.name}',
                        'location': location,
                        'type': 'storage'
                    })
            
            residency_data['resource_locations']['storage'] = bucket_locations
            
            # Compute instance locations
            instance_locations = []
            for zone, response in self.compute_client.aggregated_list(project=self.project_id):
                if response.instances:
                    zone_name = zone.split('/')[-1]
                    region = '-'.join(zone_name.split('-')[:-1])
                    for inst in response.instances:
                        instance_locations.append({
                            'resource': f'instance/{inst.name}',
                            'zone': zone_name,
                            'region': region,
                            'type': 'compute'
                        })
                        location_counts[region] = location_counts.get(region, 0) + 1
            
            residency_data['resource_locations']['compute'] = instance_locations
            
            # Database locations
            from googleapiclient import discovery
            
            # Cloud SQL locations
            try:
                sql_service = discovery.build('sqladmin', 'v1', credentials=self.credentials)
                sql_instances = sql_service.instances().list(project=self.project_id).execute()
                
                db_locations = []
                for instance in sql_instances.get('items', []):
                    region = instance.get('region', 'unknown')
                    db_locations.append({
                        'resource': f'sql/{instance.get("name")}',
                        'region': region,
                        'type': 'database'
                    })
                    location_counts[region] = location_counts.get(region, 0) + 1
                    
                    # Check for replicas in different regions
                    if instance.get('replicaConfiguration'):
                        residency_data['cross_region_replications'].append({
                            'primary': instance.get('name'),
                            'primaryRegion': region,
                            'replicationType': 'sql'
                        })
                
                residency_data['resource_locations']['databases'] = db_locations
            except:
                pass
            
            # BigQuery dataset locations
            try:
                bq_service = discovery.build('bigquery', 'v2', credentials=self.credentials)
                datasets = bq_service.datasets().list(projectId=self.project_id).execute()
                
                bq_locations = []
                for dataset in datasets.get('datasets', []):
                    ds_info = bq_service.datasets().get(
                        projectId=self.project_id,
                        datasetId=dataset['datasetReference']['datasetId']
                    ).execute()
                    
                    location = ds_info.get('location', 'unknown').lower()
                    bq_locations.append({
                        'resource': f'bigquery/{dataset["datasetReference"]["datasetId"]}',
                        'location': location,
                        'type': 'bigquery'
                    })
                    location_counts[location] = location_counts.get(location, 0) + 1
                    
                    if location in ['us', 'eu']:
                        residency_data['multi_region_resources'].append({
                            'resource': f'bigquery/{dataset["datasetReference"]["datasetId"]}',
                            'location': location,
                            'type': 'bigquery'
                        })
                
                residency_data['resource_locations']['bigquery'] = bq_locations
            except:
                pass
            
            # Location distribution summary
            residency_data['location_distribution'] = location_counts
            
            # Check for location constraints
            try:
                org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
                
                location_constraint = org_service.projects().getEffectiveOrgPolicy(
                    resource=f'projects/{self.project_id}',
                    body={'constraint': 'constraints/gcp.resourceLocations'}
                ).execute()
                
                residency_data['location_constraints'] = location_constraint
            except:
                residency_data['location_constraints'] = None
            
        except Exception as e:
            print(f"Error collecting data residency information: {e}")
            residency_data['error'] = str(e)
        
        return residency_data
    
    def collect_api_security(self) -> Dict[str, Any]:
        """Collect API activation, quotas, and security settings"""
        print("\n[Security] Collecting API security configurations...")
        api_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'enabled_apis': [],
            'api_keys': [],
            'quota_metrics': [],
            'service_account_api_usage': {}
        }
        
        try:
            from googleapiclient import discovery
            
            # Get all enabled APIs with detailed info
            service_usage = discovery.build('serviceusage', 'v1', credentials=self.credentials)
            
            enabled_apis = service_usage.services().list(
                parent=f'projects/{self.project_id}',
                filter='state:ENABLED',
                pageSize=200
            ).execute()
            
            for api in enabled_apis.get('services', []):
                api_info = {
                    'name': api.get('name', '').split('/')[-1],
                    'displayName': api.get('config', {}).get('title'),
                    'state': api.get('state')
                }
                
                # Try to get activation date from config
                if 'config' in api:
                    api_info['documentation'] = api['config'].get('documentation', {}).get('summary')
                
                api_data['enabled_apis'].append(api_info)
                
                # Get quota information for critical APIs
                if api_info['name'] in ['compute.googleapis.com', 'storage.googleapis.com', 
                                       'bigquery.googleapis.com', 'container.googleapis.com']:
                    try:
                        # Get service quotas
                        quotas = service_usage.services().consumerQuotaMetrics().list(
                            parent=api.get('name')
                        ).execute()
                        
                        for metric in quotas.get('metrics', []):
                            api_data['quota_metrics'].append({
                                'api': api_info['name'],
                                'metric': metric.get('name'),
                                'displayName': metric.get('displayName'),
                                'unit': metric.get('unit')
                            })
                    except:
                        pass
            
            # Get API keys with restrictions
            try:
                apikeys_service = discovery.build('apikeys', 'v2', credentials=self.credentials)
                keys = apikeys_service.projects().locations().keys().list(
                    parent=f'projects/{self.project_id}/locations/global'
                ).execute()
                
                for key in keys.get('keys', []):
                    key_info = {
                        'name': key.get('name', '').split('/')[-1],
                        'displayName': key.get('displayName'),
                        'createTime': key.get('createTime'),
                        'restrictions': {}
                    }
                    
                    # Analyze restrictions
                    restrictions = key.get('restrictions', {})
                    
                    # API restrictions
                    if 'apiTargets' in restrictions:
                        key_info['restrictions']['apiTargets'] = [
                            target.get('service') for target in restrictions['apiTargets']
                        ]
                    else:
                        key_info['restrictions']['apiTargets'] = 'Unrestricted'
                    
                    # Browser restrictions
                    if 'browserKeyRestrictions' in restrictions:
                        key_info['restrictions']['allowedReferrers'] = \
                            restrictions['browserKeyRestrictions'].get('allowedReferrers', [])
                    
                    # Server restrictions
                    if 'serverKeyRestrictions' in restrictions:
                        key_info['restrictions']['allowedIps'] = \
                            restrictions['serverKeyRestrictions'].get('allowedIps', [])
                    
                    # Android restrictions
                    if 'androidKeyRestrictions' in restrictions:
                        key_info['restrictions']['allowedApplications'] = \
                            restrictions['androidKeyRestrictions'].get('allowedApplications', [])
                    
                    # iOS restrictions
                    if 'iosKeyRestrictions' in restrictions:
                        key_info['restrictions']['allowedBundleIds'] = \
                            restrictions['iosKeyRestrictions'].get('allowedBundleIds', [])
                    
                    api_data['api_keys'].append(key_info)
            except:
                pass
            
            # Analyze service account API usage patterns
            iam_service = discovery.build('iam', 'v1', credentials=self.credentials)
            
            try:
                sa_list = iam_service.projects().serviceAccounts().list(
                    name=f'projects/{self.project_id}'
                ).execute()
                
                # For each service account, check which APIs it might use based on roles
                crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
                policy = crm_service.projects().getIamPolicy(
                    resource=f'projects/{self.project_id}'
                ).execute()
                
                for sa in sa_list.get('accounts', []):
                    sa_email = sa.get('email')
                    sa_apis = set()
                    
                    # Find roles for this service account
                    for binding in policy.get('bindings', []):
                        if f'serviceAccount:{sa_email}' in binding.get('members', []):
                            role = binding.get('role')
                            # Map roles to likely API usage
                            if 'compute' in role:
                                sa_apis.add('compute.googleapis.com')
                            if 'storage' in role:
                                sa_apis.add('storage.googleapis.com')
                            if 'bigquery' in role:
                                sa_apis.add('bigquery.googleapis.com')
                            if 'container' in role:
                                sa_apis.add('container.googleapis.com')
                    
                    if sa_apis:
                        api_data['service_account_api_usage'][sa_email] = list(sa_apis)
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting API security data: {e}")
            api_data['error'] = str(e)
        
        return api_data
    
    def collect_binary_authorization(self) -> Dict[str, Any]:
        """Collect Binary Authorization policies and attestations"""
        print("\n[Security] Collecting Binary Authorization configurations...")
        binauth_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'policy': None,
            'attestors': [],
            'container_analysis': {},
            'admission_rules': []
        }
        
        try:
            from googleapiclient import discovery
            
            # Get Binary Authorization policy
            try:
                binauth_service = discovery.build('binaryauthorization', 'v1', credentials=self.credentials)
                
                policy = binauth_service.projects().getPolicy(
                    name=f'projects/{self.project_id}/policy'
                ).execute()
                
                binauth_data['policy'] = {
                    'admissionWhitelistPatterns': policy.get('admissionWhitelistPatterns', []),
                    'globalPolicyEvaluationMode': policy.get('globalPolicyEvaluationMode'),
                    'defaultAdmissionRule': policy.get('defaultAdmissionRule'),
                    'clusterAdmissionRules': policy.get('clusterAdmissionRules', {}),
                    'kubernetesNamespaceAdmissionRules': policy.get('kubernetesNamespaceAdmissionRules', {}),
                    'kubernetesServiceAccountAdmissionRules': policy.get('kubernetesServiceAccountAdmissionRules', {}),
                    'istioServiceIdentityAdmissionRules': policy.get('istioServiceIdentityAdmissionRules', {})
                }
                
                # Analyze admission rules
                default_rule = policy.get('defaultAdmissionRule', {})
                if default_rule:
                    binauth_data['admission_rules'].append({
                        'type': 'default',
                        'evaluationMode': default_rule.get('evaluationMode'),
                        'enforcementMode': default_rule.get('enforcementMode'),
                        'requireAttestationsBy': default_rule.get('requireAttestationsBy', [])
                    })
                
                # Get attestors
                attestors = binauth_service.projects().attestors().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                
                for attestor in attestors.get('attestors', []):
                    attestor_info = {
                        'name': attestor.get('name', '').split('/')[-1],
                        'description': attestor.get('description'),
                        'updateTime': attestor.get('updateTime')
                    }
                    
                    # Get public keys
                    if 'userOwnedGrafeasNote' in attestor:
                        attestor_info['noteReference'] = attestor['userOwnedGrafeasNote'].get('noteReference')
                        attestor_info['publicKeys'] = len(attestor['userOwnedGrafeasNote'].get('publicKeys', []))
                    
                    binauth_data['attestors'].append(attestor_info)
                    
            except Exception as e:
                if 'not found' not in str(e).lower():
                    print(f"Binary Authorization not configured or accessible: {e}")
            
            # Get container vulnerability data
            try:
                container_analysis = discovery.build('containeranalysis', 'v1', credentials=self.credentials)
                
                # Get vulnerability occurrences
                vulnerabilities = container_analysis.projects().occurrences().list(
                    parent=f'projects/{self.project_id}',
                    filter='kind="VULNERABILITY"',
                    pageSize=500
                ).execute()
                
                # Analyze vulnerabilities by severity
                vuln_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
                vuln_by_image = {}
                
                for vuln in vulnerabilities.get('occurrences', []):
                    severity = vuln.get('vulnerability', {}).get('severity', 'UNKNOWN')
                    if severity in vuln_by_severity:
                        vuln_by_severity[severity] += 1
                    
                    # Track by image
                    resource_uri = vuln.get('resourceUri', '')
                    if resource_uri:
                        image_name = resource_uri.split('/')[-1].split('@')[0]
                        if image_name not in vuln_by_image:
                            vuln_by_image[image_name] = {'total': 0, 'critical': 0, 'high': 0}
                        vuln_by_image[image_name]['total'] += 1
                        if severity == 'CRITICAL':
                            vuln_by_image[image_name]['critical'] += 1
                        elif severity == 'HIGH':
                            vuln_by_image[image_name]['high'] += 1
                
                binauth_data['container_analysis'] = {
                    'vulnerabilities_by_severity': vuln_by_severity,
                    'vulnerabilities_by_image': vuln_by_image,
                    'total_vulnerabilities': sum(vuln_by_severity.values())
                }
                
                # Get attestation occurrences
                attestations = container_analysis.projects().occurrences().list(
                    parent=f'projects/{self.project_id}',
                    filter='kind="ATTESTATION"',
                    pageSize=100
                ).execute()
                
                binauth_data['container_analysis']['attestation_count'] = len(attestations.get('occurrences', []))
                
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting Binary Authorization data: {e}")
            binauth_data['error'] = str(e)
        
        return binauth_data
    
    def collect_waf_configurations(self) -> Dict[str, Any]:
        """Collect detailed Cloud Armor WAF configurations"""
        print("\n[Security] Collecting Cloud Armor WAF configurations...")
        waf_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'security_policies': [],
            'edge_security_policies': [],
            'managed_protection_tiers': [],
            'threat_intelligence': {}
        }
        
        try:
            # Get all security policies
            security_policies_client = compute_v1.SecurityPoliciesClient()
            
            for policy in security_policies_client.list(project=self.project_id):
                policy_info = {
                    'name': policy.name,
                    'description': policy.description,
                    'creationTimestamp': policy.creation_timestamp,
                    'fingerprint': policy.fingerprint,
                    'rules': [],
                    'adaptiveProtectionConfig': None,
                    'advancedOptionsConfig': None,
                    'type': policy.type_
                }
                
                # Process rules
                for rule in policy.rules or []:
                    rule_info = {
                        'priority': rule.priority,
                        'action': rule.action,
                        'preview': rule.preview,
                        'description': rule.description,
                        'match': None,
                        'preconfiguredWafConfig': None,
                        'rateLimitOptions': None
                    }
                    
                    # Match conditions
                    if rule.match:
                        rule_info['match'] = {
                            'versionedExpr': rule.match.versioned_expr,
                            'expr': {
                                'expression': rule.match.expr.expression if rule.match.expr else None,
                                'title': rule.match.expr.title if rule.match.expr else None
                            } if rule.match.expr else None
                        }
                    
                    # Preconfigured WAF rules
                    if hasattr(rule, 'preconfigured_waf_config') and rule.preconfigured_waf_config:
                        waf_config = rule.preconfigured_waf_config
                        rule_info['preconfiguredWafConfig'] = {
                            'exclusions': []
                        }
                        
                        # Process exclusions
                        for exclusion in waf_config.exclusions or []:
                            rule_info['preconfiguredWafConfig']['exclusions'].append({
                                'targetRuleSet': exclusion.target_rule_set,
                                'targetRuleIds': list(exclusion.target_rule_ids) if exclusion.target_rule_ids else [],
                                'requestHeadersToExclude': [{
                                    'val': h.val,
                                    'op': h.op
                                } for h in exclusion.request_headers_to_exclude or []],
                                'requestCookiesToExclude': [{
                                    'val': c.val,
                                    'op': c.op
                                } for c in exclusion.request_cookies_to_exclude or []],
                                'requestQueryParamsToExclude': [{
                                    'val': q.val,
                                    'op': q.op
                                } for q in exclusion.request_query_params_to_exclude or []],
                                'requestUrisToExclude': [{
                                    'val': u.val,
                                    'op': u.op
                                } for u in exclusion.request_uris_to_exclude or []]
                            })
                    
                    # Rate limiting
                    if hasattr(rule, 'rate_limit_options') and rule.rate_limit_options:
                        rule_info['rateLimitOptions'] = {
                            'conformAction': rule.rate_limit_options.conform_action,
                            'exceedAction': rule.rate_limit_options.exceed_action,
                            'enforceOnKey': rule.rate_limit_options.enforce_on_key,
                            'enforceOnKeyName': rule.rate_limit_options.enforce_on_key_name,
                            'thresholdCount': rule.rate_limit_options.rate_limit_threshold.count if rule.rate_limit_options.rate_limit_threshold else None,
                            'thresholdIntervalSec': rule.rate_limit_options.rate_limit_threshold.interval_sec if rule.rate_limit_options.rate_limit_threshold else None
                        }
                    
                    policy_info['rules'].append(rule_info)
                
                # Adaptive protection
                if hasattr(policy, 'adaptive_protection_config') and policy.adaptive_protection_config:
                    policy_info['adaptiveProtectionConfig'] = {
                        'layer7DdosDefenseConfig': {
                            'enable': policy.adaptive_protection_config.layer_7_ddos_defense_config.enable if policy.adaptive_protection_config.layer_7_ddos_defense_config else False,
                            'ruleVisibility': policy.adaptive_protection_config.layer_7_ddos_defense_config.rule_visibility if policy.adaptive_protection_config.layer_7_ddos_defense_config else None
                        }
                    }
                
                # Advanced options
                if hasattr(policy, 'advanced_options_config') and policy.advanced_options_config:
                    policy_info['advancedOptionsConfig'] = {
                        'jsonParsing': policy.advanced_options_config.json_parsing,
                        'jsonCustomConfig': policy.advanced_options_config.json_custom_config,
                        'logLevel': policy.advanced_options_config.log_level
                    }
                
                # Categorize policy
                if policy.type_ == 'CLOUD_ARMOR_EDGE':
                    waf_data['edge_security_policies'].append(policy_info)
                else:
                    waf_data['security_policies'].append(policy_info)
            
            # Check for managed protection
            managed_rules = ['owasp-crs-v030001-id942110-sqli', 'owasp-crs-v030001-id942120-sqli',
                           'owasp-crs-v030001-id942150-sqli', 'owasp-crs-v030001-id942410-sqli']
            
            for policy in waf_data['security_policies']:
                has_managed = False
                for rule in policy['rules']:
                    if rule.get('preconfiguredWafConfig'):
                        has_managed = True
                        break
                
                if has_managed:
                    waf_data['managed_protection_tiers'].append({
                        'policy': policy['name'],
                        'tier': 'OWASP CRS'
                    })
            
            # Threat intelligence summary
            waf_data['threat_intelligence'] = {
                'total_policies': len(waf_data['security_policies']) + len(waf_data['edge_security_policies']),
                'policies_with_rate_limiting': sum(1 for p in waf_data['security_policies'] 
                                                 for r in p['rules'] if r.get('rateLimitOptions')),
                'policies_with_waf_rules': sum(1 for p in waf_data['security_policies'] 
                                             for r in p['rules'] if r.get('preconfiguredWafConfig')),
                'adaptive_protection_enabled': sum(1 for p in waf_data['security_policies'] 
                                                 if p.get('adaptiveProtectionConfig'))
            }
            
        except Exception as e:
            print(f"Error collecting WAF configurations: {e}")
            waf_data['error'] = str(e)
        
        return waf_data
    
    def collect_identity_federation(self) -> Dict[str, Any]:
        """Collect workload identity and federation configurations"""
        print("\n[Identity] Collecting workload identity configurations...")
        identity_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'workload_identity_pools': [],
            'workload_identity_providers': [],
            'service_account_impersonation': [],
            'gke_workload_identity': []
        }
        
        try:
            from googleapiclient import discovery
            iam_service = discovery.build('iam', 'v1', credentials=self.credentials)
            
            # Get workload identity pools
            try:
                pools = iam_service.projects().locations().workloadIdentityPools().list(
                    parent=f'projects/{self.project_id}/locations/global'
                ).execute()
                
                for pool in pools.get('workloadIdentityPools', []):
                    pool_info = {
                        'name': pool.get('name', '').split('/')[-1],
                        'displayName': pool.get('displayName'),
                        'description': pool.get('description'),
                        'state': pool.get('state'),
                        'disabled': pool.get('disabled', False),
                        'providers': []
                    }
                    
                    # Get providers for this pool
                    try:
                        providers = iam_service.projects().locations().workloadIdentityPools().providers().list(
                            parent=pool.get('name')
                        ).execute()
                        
                        for provider in providers.get('workloadIdentityPoolProviders', []):
                            provider_info = {
                                'name': provider.get('name', '').split('/')[-1],
                                'displayName': provider.get('displayName'),
                                'description': provider.get('description'),
                                'state': provider.get('state'),
                                'disabled': provider.get('disabled', False),
                                'attributeMapping': provider.get('attributeMapping', {}),
                                'attributeCondition': provider.get('attributeCondition')
                            }
                            
                            # Get provider type
                            if 'oidc' in provider:
                                provider_info['type'] = 'oidc'
                                provider_info['issuerUri'] = provider['oidc'].get('issuerUri')
                                provider_info['allowedAudiences'] = provider['oidc'].get('allowedAudiences', [])
                            elif 'aws' in provider:
                                provider_info['type'] = 'aws'
                                provider_info['accountId'] = provider['aws'].get('accountId')
                            elif 'saml' in provider:
                                provider_info['type'] = 'saml'
                                provider_info['idpMetadataXml'] = 'Present' if provider['saml'].get('idpMetadataXml') else 'Not present'
                            
                            pool_info['providers'].append(provider_info)
                            identity_data['workload_identity_providers'].append(provider_info)
                    except:
                        pass
                    
                    identity_data['workload_identity_pools'].append(pool_info)
            except:
                pass
            
            # Check service account impersonation
            sa_list = iam_service.projects().serviceAccounts().list(
                name=f'projects/{self.project_id}'
            ).execute()
            
            crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            policy = crm_service.projects().getIamPolicy(
                resource=f'projects/{self.project_id}'
            ).execute()
            
            for sa in sa_list.get('accounts', []):
                sa_email = sa.get('email')
                impersonators = []
                
                # Check who can impersonate this service account
                for binding in policy.get('bindings', []):
                    if binding.get('role') in ['roles/iam.serviceAccountTokenCreator', 
                                              'roles/iam.serviceAccountUser']:
                        for member in binding.get('members', []):
                            if member != f'serviceAccount:{sa_email}':
                                impersonators.append({
                                    'member': member,
                                    'role': binding['role']
                                })
                
                if impersonators:
                    identity_data['service_account_impersonation'].append({
                        'serviceAccount': sa_email,
                        'impersonators': impersonators
                    })
            
            # Check GKE workload identity
            try:
                for cluster in self._get_gke_clusters():
                    if cluster.get('workloadIdentityConfig'):
                        identity_data['gke_workload_identity'].append({
                            'cluster': cluster['name'],
                            'workloadPool': cluster['workloadIdentityConfig'].get('workloadPool'),
                            'location': cluster.get('location')
                        })
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting identity federation data: {e}")
            identity_data['error'] = str(e)
        
        return identity_data
    
    def collect_key_usage_audit(self) -> Dict[str, Any]:
        """Collect which resources use which KMS keys"""
        print("\n[KMS] Collecting encryption key usage audit...")
        key_usage_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'keys_by_resource_type': {},
            'resources_by_key': {},
            'key_details': [],
            'unencrypted_resources': []
        }
        
        try:
            # Map to track key usage
            key_usage_map = {}
            
            # Check compute disk encryption
            print("  Checking compute disk encryption...")
            for zone, response in self.disks_client.aggregated_list(project=self.project_id):
                if response.disks:
                    for disk in response.disks:
                        if disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name:
                            key_name = disk.disk_encryption_key.kms_key_name
                            if key_name not in key_usage_map:
                                key_usage_map[key_name] = {'compute_disks': [], 'storage_buckets': [], 
                                                          'sql_instances': [], 'other': []}
                            key_usage_map[key_name]['compute_disks'].append({
                                'resource': f'disk/{disk.name}',
                                'zone': zone.split('/')[-1]
                            })
                        else:
                            key_usage_data['unencrypted_resources'].append({
                                'type': 'compute_disk',
                                'resource': f'disk/{disk.name}',
                                'zone': zone.split('/')[-1]
                            })
            
            # Check storage bucket encryption
            print("  Checking storage bucket encryption...")
            for bucket in self.storage_client.list_buckets():
                if bucket.default_kms_key_name:
                    key_name = bucket.default_kms_key_name
                    if key_name not in key_usage_map:
                        key_usage_map[key_name] = {'compute_disks': [], 'storage_buckets': [], 
                                                  'sql_instances': [], 'other': []}
                    key_usage_map[key_name]['storage_buckets'].append({
                        'resource': f'bucket/{bucket.name}',
                        'location': bucket.location
                    })
                else:
                    key_usage_data['unencrypted_resources'].append({
                        'type': 'storage_bucket',
                        'resource': f'bucket/{bucket.name}',
                        'location': bucket.location
                    })
            
            # Check SQL instance encryption
            from googleapiclient import discovery
            sql_service = discovery.build('sqladmin', 'v1', credentials=self.credentials)
            
            try:
                instances = sql_service.instances().list(project=self.project_id).execute()
                for instance in instances.get('items', []):
                    disk_config = instance.get('diskEncryptionConfiguration', {})
                    if disk_config.get('kmsKeyName'):
                        key_name = disk_config['kmsKeyName']
                        if key_name not in key_usage_map:
                            key_usage_map[key_name] = {'compute_disks': [], 'storage_buckets': [], 
                                                      'sql_instances': [], 'other': []}
                        key_usage_map[key_name]['sql_instances'].append({
                            'resource': f'sql/{instance["name"]}',
                            'region': instance.get('region')
                        })
                    else:
                        key_usage_data['unencrypted_resources'].append({
                            'type': 'sql_instance',
                            'resource': f'sql/{instance["name"]}',
                            'region': instance.get('region')
                        })
            except:
                pass
            
            # Get key details from KMS
            print("  Getting KMS key details...")
            locations = ['global', 'us-central1', 'us-east1', 'us-west1', 'us-east4']
            
            for location in locations:
                try:
                    parent = f"projects/{self.project_id}/locations/{location}"
                    
                    for key_ring in self.kms_client.list_key_rings(request={"parent": parent}):
                        for crypto_key in self.kms_client.list_crypto_keys(request={"parent": key_ring.name}):
                            key_info = {
                                'name': crypto_key.name,
                                'purpose': crypto_key.purpose.name if crypto_key.purpose else 'UNKNOWN',
                                'createTime': crypto_key.create_time.isoformat() if crypto_key.create_time else None,
                                'rotationPeriod': None,
                                'nextRotationTime': None,
                                'algorithm': None,
                                'protectionLevel': None,
                                'state': None
                            }
                            
                            # Get rotation info
                            if hasattr(crypto_key, 'rotation_period') and crypto_key.rotation_period:
                                key_info['rotationPeriod'] = crypto_key.rotation_period.total_seconds()
                            
                            if hasattr(crypto_key, 'next_rotation_time') and crypto_key.next_rotation_time:
                                key_info['nextRotationTime'] = crypto_key.next_rotation_time.isoformat()
                            
                            # Get primary version info
                            if crypto_key.primary:
                                version = self.kms_client.get_crypto_key_version(
                                    request={"name": crypto_key.primary.name}
                                )
                                key_info['algorithm'] = version.algorithm.name if version.algorithm else None
                                key_info['protectionLevel'] = version.protection_level.name if version.protection_level else None
                                key_info['state'] = version.state.name if version.state else None
                            
                            key_usage_data['key_details'].append(key_info)
                except:
                    pass
            
            # Convert key usage map to output format
            key_usage_data['resources_by_key'] = key_usage_map
            
            # Aggregate by resource type
            for key, resources in key_usage_map.items():
                for resource_type, resource_list in resources.items():
                    if resource_type not in key_usage_data['keys_by_resource_type']:
                        key_usage_data['keys_by_resource_type'][resource_type] = {}
                    if len(resource_list) > 0:
                        key_usage_data['keys_by_resource_type'][resource_type][key] = len(resource_list)
            
        except Exception as e:
            print(f"Error collecting key usage audit: {e}")
            key_usage_data['error'] = str(e)
        
        return key_usage_data
    
    def collect_network_endpoints(self) -> Dict[str, Any]:
        """Collect all network endpoints and their configurations"""
        print("\n[Networking] Collecting network endpoints...")
        endpoints_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'network_endpoint_groups': [],
            'serverless_negs': [],
            'internet_negs': [],
            'private_service_connect': [],
            'grpc_routes': []
        }
        
        try:
            # Get Network Endpoint Groups (NEGs)
            neg_client = compute_v1.NetworkEndpointGroupsClient()
            
            for zone, response in neg_client.aggregated_list(project=self.project_id):
                if response.network_endpoint_groups:
                    for neg in response.network_endpoint_groups:
                        neg_info = {
                            'name': neg.name,
                            'zone': zone.split('/')[-1] if 'zones/' in zone else 'global',
                            'networkEndpointType': neg.network_endpoint_type,
                            'size': neg.size,
                            'network': neg.network.split('/')[-1] if neg.network else None,
                            'subnetwork': neg.subnetwork.split('/')[-1] if neg.subnetwork else None,
                            'defaultPort': neg.default_port,
                            'cloudRun': None,
                            'appEngine': None,
                            'cloudFunction': None,
                            'pscTargetService': neg.psc_target_service
                        }
                        
                        # Check for serverless NEGs
                        if hasattr(neg, 'cloud_run') and neg.cloud_run:
                            neg_info['cloudRun'] = {
                                'service': neg.cloud_run.service,
                                'tag': neg.cloud_run.tag,
                                'urlMask': neg.cloud_run.url_mask
                            }
                            endpoints_data['serverless_negs'].append(neg_info)
                        elif hasattr(neg, 'app_engine') and neg.app_engine:
                            neg_info['appEngine'] = {
                                'service': neg.app_engine.service,
                                'version': neg.app_engine.version,
                                'urlMask': neg.app_engine.url_mask
                            }
                            endpoints_data['serverless_negs'].append(neg_info)
                        elif hasattr(neg, 'cloud_function') and neg.cloud_function:
                            neg_info['cloudFunction'] = {
                                'function': neg.cloud_function.function,
                                'urlMask': neg.cloud_function.url_mask
                            }
                            endpoints_data['serverless_negs'].append(neg_info)
                        elif neg.network_endpoint_type == 'INTERNET_FQDN_PORT' or neg.network_endpoint_type == 'INTERNET_IP_PORT':
                            endpoints_data['internet_negs'].append(neg_info)
                        else:
                            endpoints_data['network_endpoint_groups'].append(neg_info)
            
            # Get Private Service Connect endpoints
            from googleapiclient import discovery
            compute_service = discovery.build('compute', 'v1', credentials=self.credentials)
            
            # Get PSC forwarding rules (endpoints)
            for region in ['us-central1', 'us-east1', 'us-west1', 'us-east4']:
                try:
                    forwarding_rules = compute_service.forwardingRules().list(
                        project=self.project_id,
                        region=region
                    ).execute()
                    
                    for rule in forwarding_rules.get('items', []):
                        if rule.get('pscConnectionId') or rule.get('target', '').endswith('/serviceAttachments/'):
                            endpoints_data['private_service_connect'].append({
                                'name': rule.get('name'),
                                'region': region,
                                'address': rule.get('IPAddress'),
                                'target': rule.get('target', '').split('/')[-1] if rule.get('target') else None,
                                'network': rule.get('network', '').split('/')[-1] if rule.get('network') else None,
                                'pscConnectionId': rule.get('pscConnectionId'),
                                'pscConnectionStatus': rule.get('pscConnectionStatus')
                            })
                except:
                    pass
            
            # Get service attachments (PSC producer side)
            for region in ['us-central1', 'us-east1', 'us-west1', 'us-east4']:
                try:
                    attachments = compute_service.serviceAttachments().list(
                        project=self.project_id,
                        region=region
                    ).execute()
                    
                    for attachment in attachments.get('items', []):
                        endpoints_data['private_service_connect'].append({
                            'name': attachment.get('name'),
                            'region': region,
                            'type': 'serviceAttachment',
                            'connectionPreference': attachment.get('connectionPreference'),
                            'natSubnets': [s.split('/')[-1] for s in attachment.get('natSubnets', [])],
                            'consumerRejectLists': attachment.get('consumerRejectLists', []),
                            'consumerAcceptLists': attachment.get('consumerAcceptLists', [])
                        })
                except:
                    pass
            
            # Get gRPC routes if available
            try:
                networkservices = discovery.build('networkservices', 'v1', credentials=self.credentials)
                
                grpc_routes = networkservices.projects().locations().grpcRoutes().list(
                    parent=f'projects/{self.project_id}/locations/global'
                ).execute()
                
                for route in grpc_routes.get('grpcRoutes', []):
                    endpoints_data['grpc_routes'].append({
                        'name': route.get('name'),
                        'hostnames': route.get('hostnames', []),
                        'meshes': [m.split('/')[-1] for m in route.get('meshes', [])],
                        'gateways': [g.split('/')[-1] for g in route.get('gateways', [])]
                    })
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting network endpoints: {e}")
            endpoints_data['error'] = str(e)
        
        return endpoints_data
    
    def collect_os_compliance(self) -> Dict[str, Any]:
        """Collect OS-level compliance data"""
        print("\n[Compute] Collecting OS compliance data...")
        os_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'os_inventory': [],
            'patch_compliance': {},
            'security_agents': {},
            'os_distribution': {}
        }
        
        try:
            from googleapiclient import discovery
            
            # Get OS Config data
            try:
                osconfig_service = discovery.build('osconfig', 'v1', credentials=self.credentials)
                
                # Get inventory data for instances
                compute_service = discovery.build('compute', 'v1', credentials=self.credentials)
                
                # Sample up to 50 instances for OS inventory
                instance_count = 0
                instances_with_inventory = 0
                os_versions = {}
                
                for zone in ['us-central1-a', 'us-east1-b', 'us-west1-a', 'us-east4-b']:
                    try:
                        instances = compute_service.instances().list(
                            project=self.project_id,
                            zone=zone,
                            maxResults=10
                        ).execute()
                        
                        for instance in instances.get('items', []):
                            instance_count += 1
                            instance_name = instance.get('name')
                            
                            # Try to get OS inventory
                            try:
                                inventory = osconfig_service.projects().locations().instances().inventories().get(
                                    name=f'projects/{self.project_id}/locations/{zone}/instances/{instance["id"]}/inventory'
                                ).execute()
                                
                                instances_with_inventory += 1
                                
                                os_info = {
                                    'instanceName': instance_name,
                                    'zone': zone,
                                    'osInfo': {},
                                    'installedPackages': 0,
                                    'securityAgents': []
                                }
                                
                                # Get OS info
                                if inventory.get('osInfo'):
                                    os_info['osInfo'] = {
                                        'hostname': inventory['osInfo'].get('hostname'),
                                        'longName': inventory['osInfo'].get('longName'),
                                        'shortName': inventory['osInfo'].get('shortName'),
                                        'version': inventory['osInfo'].get('version'),
                                        'architecture': inventory['osInfo'].get('architecture'),
                                        'kernelVersion': inventory['osInfo'].get('kernelVersion')
                                    }
                                    
                                    # Track OS distribution
                                    os_name = inventory['osInfo'].get('shortName', 'unknown')
                                    os_versions[os_name] = os_versions.get(os_name, 0) + 1
                                
                                # Count packages
                                if inventory.get('items'):
                                    for item_type, items in inventory['items'].items():
                                        if 'Package' in item_type:
                                            os_info['installedPackages'] += len(items.get('entries', {}))
                                
                                # Check for security agents
                                security_packages = ['osconfig-agent', 'google-osconfig-agent', 
                                                   'stackdriver-agent', 'google-cloud-ops-agent',
                                                   'falcon-sensor', 'qualys-cloud-agent', 'rapid7-agent']
                                
                                if inventory.get('items', {}).get('installedPackage'):
                                    for pkg_id, pkg_info in inventory['items']['installedPackage'].get('entries', {}).items():
                                        pkg_name = pkg_info.get('installedPackage', {}).get('aptPackage', {}).get('packageName', '')
                                        if not pkg_name:
                                            pkg_name = pkg_info.get('installedPackage', {}).get('yumPackage', {}).get('packageName', '')
                                        
                                        for agent in security_packages:
                                            if agent in pkg_name.lower():
                                                os_info['securityAgents'].append(pkg_name)
                                                
                                                # Track security agents globally
                                                if agent not in os_data['security_agents']:
                                                    os_data['security_agents'][agent] = 0
                                                os_data['security_agents'][agent] += 1
                                
                                os_data['os_inventory'].append(os_info)
                                
                            except Exception as e:
                                # No inventory available for this instance
                                pass
                            
                            if instance_count >= 50:  # Limit sampling
                                break
                    except:
                        pass
                    
                    if instance_count >= 50:
                        break
                
                # Set OS distribution
                os_data['os_distribution'] = os_versions
                
                # Get patch compliance data
                try:
                    # Get patch jobs
                    patch_jobs = osconfig_service.projects().patchJobs().list(
                        parent=f'projects/{self.project_id}',
                        pageSize=10
                    ).execute()
                    
                    patch_summary = {
                        'totalPatchJobs': len(patch_jobs.get('patchJobs', [])),
                        'successfulJobs': 0,
                        'failedJobs': 0,
                        'patchDeployments': 0
                    }
                    
                    for job in patch_jobs.get('patchJobs', []):
                        if job.get('state') == 'SUCCEEDED':
                            patch_summary['successfulJobs'] += 1
                        elif job.get('state') in ['FAILED', 'TIMED_OUT']:
                            patch_summary['failedJobs'] += 1
                    
                    # Get patch deployments
                    patch_deployments = osconfig_service.projects().patchDeployments().list(
                        parent=f'projects/{self.project_id}'
                    ).execute()
                    
                    patch_summary['patchDeployments'] = len(patch_deployments.get('patchDeployments', []))
                    os_data['patch_compliance'] = patch_summary
                    
                except:
                    pass
                
                # Add summary
                os_data['summary'] = {
                    'instancesSampled': instance_count,
                    'instancesWithInventory': instances_with_inventory,
                    'inventoryCoverage': (instances_with_inventory / instance_count * 100) if instance_count > 0 else 0
                }
                
            except Exception as e:
                if 'not enabled' not in str(e).lower():
                    print(f"OS Config API error: {e}")
            
        except Exception as e:
            print(f"Error collecting OS compliance data: {e}")
            os_data['error'] = str(e)
        
        return os_data
    
    def collect_access_approval(self) -> Dict[str, Any]:
        """Collect Access Approval and Access Transparency configurations"""
        print("\n[Audit] Collecting Access Approval configurations...")
        access_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'access_approval_settings': None,
            'approval_requests': [],
            'access_transparency': {},
            'privileged_access_audit': []
        }
        
        try:
            from googleapiclient import discovery
            
            # Get Access Approval settings
            try:
                access_approval_service = discovery.build('accessapproval', 'v1', credentials=self.credentials)
                
                settings = access_approval_service.projects().getAccessApprovalSettings(
                    name=f'projects/{self.project_id}/accessApprovalSettings'
                ).execute()
                
                access_data['access_approval_settings'] = {
                    'name': settings.get('name'),
                    'notificationEmails': settings.get('notificationEmails', []),
                    'enrolledServices': [s.get('cloudProduct') for s in settings.get('enrolledServices', [])],
                    'enrolledAncestor': settings.get('enrolledAncestor'),
                    'activeKeyVersion': settings.get('activeKeyVersion'),
                    'ancestorHasActiveKeyVersion': settings.get('ancestorHasActiveKeyVersion'),
                    'invalidKeyVersion': settings.get('invalidKeyVersion')
                }
                
                # Get recent approval requests
                try:
                    requests = access_approval_service.projects().approvalRequests().list(
                        parent=f'projects/{self.project_id}',
                        pageSize=50
                    ).execute()
                    
                    for request in requests.get('approvalRequests', []):
                        access_data['approval_requests'].append({
                            'name': request.get('name'),
                            'requestedResourceName': request.get('requestedResourceName'),
                            'requestedReason': request.get('requestedReason', {}).get('detail'),
                            'requestTime': request.get('requestTime'),
                            'requestedExpiration': request.get('requestedExpiration'),
                            'approve': request.get('approve'),
                            'dismiss': request.get('dismiss')
                        })
                except:
                    pass
                    
            except Exception as e:
                if 'not found' not in str(e).lower():
                    print(f"Access Approval not configured: {e}")
                access_data['access_approval_settings'] = {'configured': False}
            
            # Check Access Transparency logs
            try:
                # Access Transparency is checked via Cloud Logging
                from googleapiclient import discovery
                logging_service = discovery.build('logging', 'v2', credentials=self.credentials)
                
                # Check if Access Transparency logs are being collected
                filter_str = 'protoPayload.serviceName="accessapproval.googleapis.com"'
                
                entries = logging_service.entries().list(
                    body={
                        'resourceNames': [f'projects/{self.project_id}'],
                        'filter': filter_str,
                        'pageSize': 10,
                        'orderBy': 'timestamp desc'
                    }
                ).execute()
                
                access_data['access_transparency'] = {
                    'logsFound': len(entries.get('entries', [])) > 0,
                    'recentLogCount': len(entries.get('entries', []))
                }
            except:
                access_data['access_transparency'] = {'logsFound': False}
            
            # Audit privileged access patterns
            try:
                # Check admin activity logs for privileged operations
                admin_filter = 'protoPayload.authorizationInfo.permission:("admin" OR "owner" OR "editor")'
                
                admin_entries = logging_service.entries().list(
                    body={
                        'resourceNames': [f'projects/{self.project_id}'],
                        'filter': admin_filter,
                        'pageSize': 20,
                        'orderBy': 'timestamp desc'
                    }
                ).execute()
                
                privileged_actions = {}
                for entry in admin_entries.get('entries', []):
                    proto_payload = entry.get('protoPayload', {})
                    principal = proto_payload.get('authenticationInfo', {}).get('principalEmail', 'unknown')
                    
                    for auth_info in proto_payload.get('authorizationInfo', []):
                        permission = auth_info.get('permission', '')
                        if any(priv in permission.lower() for priv in ['admin', 'owner', 'editor', 'create', 'delete']):
                            if principal not in privileged_actions:
                                privileged_actions[principal] = []
                            privileged_actions[principal].append({
                                'permission': permission,
                                'resource': auth_info.get('resource'),
                                'granted': auth_info.get('granted', False)
                            })
                
                for principal, actions in privileged_actions.items():
                    access_data['privileged_access_audit'].append({
                        'principal': principal,
                        'privilegedActionCount': len(actions),
                        'sampleActions': actions[:5]  # First 5 actions as sample
                    })
                    
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting access approval data: {e}")
            access_data['error'] = str(e)
        
        return access_data
    
    def collect_resource_hierarchy(self) -> Dict[str, Any]:
        """Collect folder/project hierarchy and policy inheritance"""
        print("\n[IAM] Collecting resource hierarchy...")
        hierarchy_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'project_info': {},
            'parent_hierarchy': [],
            'inherited_policies': [],
            'folder_iam_policies': [],
            'hierarchical_firewall_policies': []
        }
        
        try:
            from googleapiclient import discovery
            crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            
            # Get project details
            project = crm_service.projects().get(name=f'projects/{self.project_id}').execute()
            
            hierarchy_data['project_info'] = {
                'name': project.get('name'),
                'projectId': project.get('projectId'),
                'displayName': project.get('displayName'),
                'state': project.get('state'),
                'createTime': project.get('createTime'),
                'updateTime': project.get('updateTime'),
                'parent': project.get('parent'),
                'labels': project.get('labels', {})
            }
            
            # Trace up the hierarchy
            current_resource = project.get('parent')
            hierarchy_level = 0
            
            while current_resource and hierarchy_level < 10:  # Prevent infinite loops
                try:
                    if current_resource.startswith('folders/'):
                        # Get folder details
                        folder = crm_service.folders().get(name=current_resource).execute()
                        
                        hierarchy_data['parent_hierarchy'].append({
                            'level': hierarchy_level,
                            'type': 'folder',
                            'name': folder.get('name'),
                            'displayName': folder.get('displayName'),
                            'state': folder.get('state'),
                            'parent': folder.get('parent')
                        })
                        
                        # Get folder IAM policy
                        try:
                            folder_policy = crm_service.folders().getIamPolicy(
                                resource=current_resource
                            ).execute()
                            
                            hierarchy_data['folder_iam_policies'].append({
                                'folder': current_resource,
                                'level': hierarchy_level,
                                'bindingsCount': len(folder_policy.get('bindings', [])),
                                'bindings': folder_policy.get('bindings', [])
                            })
                            
                            # Check for inherited roles
                            for binding in folder_policy.get('bindings', []):
                                if binding.get('role') in ['roles/owner', 'roles/editor', 'roles/viewer']:
                                    hierarchy_data['inherited_policies'].append({
                                        'source': current_resource,
                                        'level': hierarchy_level,
                                        'role': binding.get('role'),
                                        'members': binding.get('members', [])
                                    })
                        except:
                            pass
                        
                        current_resource = folder.get('parent')
                        
                    elif current_resource.startswith('organizations/'):
                        # Get organization details
                        org_id = current_resource.split('/')[-1]
                        orgs = crm_service.organizations().search().execute()
                        
                        for org in orgs.get('organizations', []):
                            if org.get('name') == current_resource:
                                hierarchy_data['parent_hierarchy'].append({
                                    'level': hierarchy_level,
                                    'type': 'organization',
                                    'name': org.get('name'),
                                    'displayName': org.get('displayName'),
                                    'state': org.get('state')
                                })
                                break
                        
                        # No parent above organization
                        current_resource = None
                    else:
                        # Unknown resource type
                        current_resource = None
                        
                except Exception as e:
                    print(f"Error traversing hierarchy at level {hierarchy_level}: {e}")
                    current_resource = None
                
                hierarchy_level += 1
            
            # Get hierarchical firewall policies
            try:
                compute_service = discovery.build('compute', 'v1', credentials=self.credentials)
                
                # Check for firewall policies associated with folders/org
                if hierarchy_data['parent_hierarchy']:
                    for parent in hierarchy_data['parent_hierarchy']:
                        if parent['type'] == 'folder':
                            try:
                                # Try to list firewall policies for this folder
                                folder_id = parent['name'].split('/')[-1]
                                policies = compute_service.firewallPolicies().list(
                                    parentId=f'folders/{folder_id}'
                                ).execute()
                                
                                for policy in policies.get('items', []):
                                    hierarchy_data['hierarchical_firewall_policies'].append({
                                        'name': policy.get('name'),
                                        'parent': parent['name'],
                                        'ruleTupleCount': policy.get('ruleTupleCount'),
                                        'description': policy.get('description')
                                    })
                            except:
                                pass
            except:
                pass
            
        except Exception as e:
            print(f"Error collecting resource hierarchy: {e}")
            hierarchy_data['error'] = str(e)
        
        return hierarchy_data
    
    def collect_vpc_sharing(self) -> Dict[str, Any]:
        """Collect Shared VPC and peering configurations"""
        print("\n[Networking] Collecting Shared VPC and peering data...")
        vpc_sharing_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'shared_vpc_host': None,
            'shared_vpc_service_projects': [],
            'vpc_peerings': [],
            'shared_subnets': [],
            'cross_project_access': []
        }
        
        try:
            from googleapiclient import discovery
            compute_service = discovery.build('compute', 'v1', credentials=self.credentials)
            
            # Check if this project is a Shared VPC host
            try:
                project_info = compute_service.projects().get(project=self.project_id).execute()
                
                if project_info.get('xpnProjectStatus') == 'HOST':
                    vpc_sharing_data['shared_vpc_host'] = {
                        'projectId': self.project_id,
                        'status': 'HOST',
                        'defaultServiceAccount': project_info.get('defaultServiceAccount')
                    }
                    
                    # Get associated service projects
                    try:
                        xpn_resources = compute_service.projects().getXpnResources(
                            project=self.project_id
                        ).execute()
                        
                        for resource in xpn_resources.get('resources', []):
                            vpc_sharing_data['shared_vpc_service_projects'].append({
                                'id': resource.get('id'),
                                'type': resource.get('type')
                            })
                    except:
                        pass
                        
                elif project_info.get('xpnProjectStatus') == 'UNSPECIFIED':
                    # Check if it's a service project
                    try:
                        host_project = compute_service.projects().getXpnHost(
                            project=self.project_id
                        ).execute()
                        
                        if host_project:
                            vpc_sharing_data['shared_vpc_host'] = {
                                'projectId': host_project.get('name'),
                                'status': 'SERVICE_PROJECT',
                                'hostProject': host_project
                            }
                    except:
                        pass
            except:
                pass
            
            # Get VPC peering connections
            networks = compute_service.networks().list(project=self.project_id).execute()
            
            for network in networks.get('items', []):
                network_name = network.get('name')
                
                # Get peerings for this network
                if network.get('peerings'):
                    for peering in network['peerings']:
                        peering_info = {
                            'name': peering.get('name'),
                            'network': network_name,
                            'peerNetwork': peering.get('network', '').split('/')[-1],
                            'peerProject': peering.get('network', '').split('/')[-3] if '/' in peering.get('network', '') else None,
                            'state': peering.get('state'),
                            'stateDetails': peering.get('stateDetails'),
                            'autoCreateRoutes': peering.get('autoCreateRoutes'),
                            'exportCustomRoutes': peering.get('exportCustomRoutes'),
                            'importCustomRoutes': peering.get('importCustomRoutes'),
                            'exchangeSubnetRoutes': peering.get('exchangeSubnetRoutes')
                        }
                        vpc_sharing_data['vpc_peerings'].append(peering_info)
                
                # Check for shared subnets if this is a host project
                if vpc_sharing_data['shared_vpc_host'] and vpc_sharing_data['shared_vpc_host']['status'] == 'HOST':
                    # Get subnets and check secondary ranges
                    try:
                        for region in ['us-central1', 'us-east1', 'us-west1', 'us-east4']:
                            subnets = compute_service.subnetworks().list(
                                project=self.project_id,
                                region=region
                            ).execute()
                            
                            for subnet in subnets.get('items', []):
                                if subnet.get('network', '').endswith(f'/{network_name}'):
                                    subnet_info = {
                                        'name': subnet.get('name'),
                                        'region': region,
                                        'network': network_name,
                                        'ipCidrRange': subnet.get('ipCidrRange'),
                                        'secondaryIpRanges': subnet.get('secondaryIpRanges', [])
                                    }
                                    vpc_sharing_data['shared_subnets'].append(subnet_info)
                    except:
                        pass
            
            # Check cross-project access via IAM
            crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            policy = crm_service.projects().getIamPolicy(
                resource=f'projects/{self.project_id}'
            ).execute()
            
            cross_project_members = set()
            for binding in policy.get('bindings', []):
                for member in binding.get('members', []):
                    # Look for service accounts from other projects
                    if member.startswith('serviceAccount:') and '@' in member:
                        sa_email = member.replace('serviceAccount:', '')
                        if '.iam.gserviceaccount.com' in sa_email:
                            sa_project = sa_email.split('@')[1].split('.')[0]
                            if sa_project != self.project_id:
                                cross_project_members.add((sa_project, sa_email, binding.get('role')))
            
            for project, email, role in cross_project_members:
                vpc_sharing_data['cross_project_access'].append({
                    'sourceProject': project,
                    'serviceAccount': email,
                    'role': role
                })
            
        except Exception as e:
            print(f"Error collecting VPC sharing data: {e}")
            vpc_sharing_data['error'] = str(e)
        
        return vpc_sharing_data
    
    def collect_essential_contacts(self) -> Dict[str, Any]:
        """Collect essential contacts for security notifications"""
        print("\n[Compliance] Collecting essential contacts...")
        contacts_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'essential_contacts': [],
            'notification_channels': [],
            'security_contacts': [],
            'incident_contacts': []
        }
        
        try:
            from googleapiclient import discovery
            
            # Get Essential Contacts
            try:
                essentialcontacts_service = discovery.build('essentialcontacts', 'v1', credentials=self.credentials)
                
                # Get contacts for the project
                contacts = essentialcontacts_service.projects().contacts().list(
                    parent=f'projects/{self.project_id}'
                ).execute()
                
                for contact in contacts.get('contacts', []):
                    contact_info = {
                        'name': contact.get('name'),
                        'email': contact.get('email'),
                        'notificationCategorySubscriptions': contact.get('notificationCategorySubscriptions', []),
                        'languageTag': contact.get('languageTag'),
                        'validationState': contact.get('validationState'),
                        'validateTime': contact.get('validateTime')
                    }
                    
                    contacts_data['essential_contacts'].append(contact_info)
                    
                    # Categorize by notification type
                    if 'SECURITY' in contact.get('notificationCategorySubscriptions', []):
                        contacts_data['security_contacts'].append(contact_info)
                    
                    if 'TECHNICAL_INCIDENTS' in contact.get('notificationCategorySubscriptions', []):
                        contacts_data['incident_contacts'].append(contact_info)
                        
            except Exception as e:
                if 'not enabled' not in str(e).lower():
                    print(f"Essential Contacts API error: {e}")
            
            # Get monitoring notification channels
            try:
                monitoring_client = monitoring_v3.NotificationChannelServiceClient(credentials=self.credentials)
                
                channels = monitoring_client.list_notification_channels(
                    name=f'projects/{self.project_id}'
                )
                
                for channel in channels:
                    channel_info = {
                        'name': channel.name,
                        'type': channel.type_,
                        'displayName': channel.display_name,
                        'description': channel.description,
                        'enabled': channel.enabled,
                        'verificationStatus': channel.verification_status.name if channel.verification_status else None,
                        'labels': dict(channel.labels) if channel.labels else {}
                    }
                    
                    # Mask sensitive data
                    if channel.type_ == 'email':
                        email = channel.labels.get('email_address', '')
                        if email:
                            # Partially mask email
                            parts = email.split('@')
                            if len(parts) == 2:
                                masked = parts[0][:3] + '***@' + parts[1]
                                channel_info['labels']['email_address'] = masked
                    
                    contacts_data['notification_channels'].append(channel_info)
                    
            except Exception as e:
                print(f"Error getting notification channels: {e}")
            
            # Add summary
            contacts_data['summary'] = {
                'totalContacts': len(contacts_data['essential_contacts']),
                'securityContacts': len(contacts_data['security_contacts']),
                'incidentContacts': len(contacts_data['incident_contacts']),
                'notificationChannels': len(contacts_data['notification_channels']),
                'hasSecurityContacts': len(contacts_data['security_contacts']) > 0,
                'hasIncidentContacts': len(contacts_data['incident_contacts']) > 0
            }
            
        except Exception as e:
            print(f"Error collecting essential contacts: {e}")
            contacts_data['error'] = str(e)
        
        return contacts_data
    
    def _analyze_excluded_logs(self, log_sinks: List[Dict]) -> List[str]:
        """Analyze which logs might be excluded"""
        excluded = []
        for sink in log_sinks:
            if sink.get('exclusions'):
                for exclusion in sink['exclusions']:
                    if not exclusion.get('disabled'):
                        excluded.append(exclusion.get('filter', ''))
        return excluded
    
    def _get_gke_clusters(self) -> List[Dict]:
        """Get GKE cluster information"""
        clusters = []
        try:
            zones = ['us-central1-a', 'us-central1-b', 'us-central1-c', 
                    'us-east1-b', 'us-east1-c', 'us-east1-d']
            
            for zone in zones:
                try:
                    cluster_list = self.container_client.list_clusters(
                        parent=f'projects/{self.project_id}/locations/{zone}'
                    )
                    for cluster in cluster_list.clusters:
                        clusters.append({
                            'name': cluster.name,
                            'location': zone,
                            'workloadIdentityConfig': cluster.workload_identity_config
                        })
                except:
                    pass
        except:
            pass
        return clusters
    
    def collect_mfa_policies(self) -> Dict[str, Any]:
        """Collect MFA/2FA enforcement policies and configurations"""
        print("\n[Security] Checking MFA/2FA policies and enforcement...")
        mfa_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'mfa_enforcement': {
                'organization_level': False,
                'conditional_access': [],
                'identity_aware_proxy': False,
                'workspace_enforcement': None
            },
            'findings': [],
            'recommendations': [],
            'iam_conditions': [],
            'high_privilege_accounts': []
        }
        
        try:
            from googleapiclient import discovery
            
            # Check for IAM conditions that might enforce MFA
            crm_service = discovery.build('cloudresourcemanager', 'v3', credentials=self.credentials)
            policy = crm_service.projects().getIamPolicy(
                resource=f'projects/{self.project_id}'
            ).execute()
            
            # Analyze IAM bindings for conditions
            for binding in policy.get('bindings', []):
                role = binding.get('role', '')
                condition = binding.get('condition', {})
                
                # Check if this is a high-privilege role
                high_privilege_roles = [
                    'roles/owner', 'roles/editor', 'roles/iam.securityAdmin',
                    'roles/compute.admin', 'roles/storage.admin', 'roles/billing.admin'
                ]
                
                if role in high_privilege_roles:
                    members = binding.get('members', [])
                    user_members = [m for m in members if m.startswith('user:')]
                    
                    if user_members:
                        mfa_data['high_privilege_accounts'].append({
                            'role': role,
                            'users': user_members,
                            'hasCondition': bool(condition),
                            'condition': condition
                        })
                        
                        if not condition:
                            mfa_data['findings'].append({
                                'severity': 'HIGH',
                                'finding': f'High-privilege role {role} assigned without conditions',
                                'affected_users': user_members,
                                'recommendation': 'Add IAM conditions to require MFA for high-privilege roles'
                            })
                
                # Check for MFA-related conditions
                if condition:
                    expression = condition.get('expression', '')
                    # Look for common MFA condition patterns
                    mfa_keywords = ['mfa', '2fa', 'two-factor', 'multi-factor', 'authenticator']
                    if any(keyword in expression.lower() for keyword in mfa_keywords):
                        mfa_data['iam_conditions'].append({
                            'role': role,
                            'condition': condition,
                            'members': binding.get('members', [])
                        })
                        mfa_data['mfa_enforcement']['conditional_access'].append({
                            'type': 'IAM Condition',
                            'role': role,
                            'expression': expression
                        })
            
            # Check organization policies for authentication requirements
            try:
                org_service = discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
                
                # Check for identity-related constraints
                identity_constraints = [
                    'iam.allowedPolicyMemberDomains',
                    'iam.disableServiceAccountKeyCreation',
                    'iam.disableServiceAccountCreation'
                ]
                
                for constraint in identity_constraints:
                    try:
                        response = org_service.projects().getEffectiveOrgPolicy(
                            resource=f'projects/{self.project_id}',
                            body={'constraint': f'constraints/{constraint}'}
                        ).execute()
                        
                        if 'listPolicy' in response:
                            allowed_domains = response['listPolicy'].get('allowedValues', [])
                            if allowed_domains:
                                mfa_data['mfa_enforcement']['organization_level'] = True
                                mfa_data['findings'].append({
                                    'severity': 'INFO',
                                    'finding': f'Domain restrictions enforced: {constraint}',
                                    'details': allowed_domains
                                })
                    except:
                        pass
            except:
                pass
            
            # Check for Identity-Aware Proxy (IAP) configuration
            try:
                iap_service = discovery.build('iap', 'v1', credentials=self.credentials)
                # Check if IAP is configured (which can enforce authentication)
                try:
                    iap_settings = iap_service.projects().iap_web().getIamPolicy(
                        resource=f'projects/{self.project_id}/iap_web'
                    ).execute()
                    if iap_settings.get('bindings'):
                        mfa_data['mfa_enforcement']['identity_aware_proxy'] = True
                        mfa_data['findings'].append({
                            'severity': 'GOOD',
                            'finding': 'Identity-Aware Proxy (IAP) is configured',
                            'details': 'IAP can enforce additional authentication requirements'
                        })
                except:
                    pass
            except:
                pass
            
            # Check enabled APIs for security services
            try:
                service_usage = discovery.build('serviceusage', 'v1', credentials=self.credentials)
                services = service_usage.services().list(
                    parent=f'projects/{self.project_id}',
                    filter='state:ENABLED'
                ).execute()
                
                security_apis = []
                for service in services.get('services', []):
                    service_name = service.get('config', {}).get('name', '')
                    if any(api in service_name for api in ['identitytoolkit', 'iap', 'cloudidentity']):
                        security_apis.append(service_name)
                
                if security_apis:
                    mfa_data['enabled_security_apis'] = security_apis
            except:
                pass
            
            # Generate recommendations based on findings
            if not mfa_data['mfa_enforcement']['conditional_access']:
                mfa_data['recommendations'].append({
                    'priority': 'HIGH',
                    'recommendation': 'Implement IAM conditions to enforce MFA for high-privilege roles',
                    'details': 'Use CEL expressions in IAM conditions to require MFA authentication'
                })
            
            if not mfa_data['mfa_enforcement']['identity_aware_proxy']:
                mfa_data['recommendations'].append({
                    'priority': 'MEDIUM',
                    'recommendation': 'Consider implementing Identity-Aware Proxy (IAP)',
                    'details': 'IAP provides context-aware access control and can enforce additional authentication'
                })
            
            if mfa_data['high_privilege_accounts']:
                total_high_priv = sum(len(acc['users']) for acc in mfa_data['high_privilege_accounts'])
                mfa_data['recommendations'].append({
                    'priority': 'HIGH',
                    'recommendation': f'Review and secure {total_high_priv} high-privilege user accounts',
                    'details': 'Ensure all administrative accounts use MFA and have appropriate conditions'
                })
            
            # Calculate MFA score
            mfa_score = 0
            if mfa_data['mfa_enforcement']['organization_level']:
                mfa_score += 30
            if mfa_data['mfa_enforcement']['conditional_access']:
                mfa_score += 40
            if mfa_data['mfa_enforcement']['identity_aware_proxy']:
                mfa_score += 30
            
            mfa_data['mfa_compliance_score'] = mfa_score
            
        except Exception as e:
            print(f"Error checking MFA policies: {e}")
            mfa_data['error'] = str(e)
        
        return mfa_data


def main():
    parser = argparse.ArgumentParser(description='FedRAMP 20x GCP Data Collector')
    parser.add_argument('--project', help='GCP Project ID', default=None)
    parser.add_argument('--full', action='store_true', help='Run full collection')
    args = parser.parse_args()
    
    collector = FedRAMP20xCollector(project_id=args.project)
    collector.collect_all_resources_parallel()


if __name__ == '__main__':
    main()
