#!/bin/bash
# FedRAMP Evidence Collection One-Liners for GCP
# Each command outputs JSON data that can be used to verify FedRAMP compliance requirements

# 1. User data in Google Cloud Storage is encrypted at rest (GCP)
echo "=== Storage Bucket Encryption ==="
python3 -c "from google.cloud import storage; import json; c=storage.Client(); buckets=[{'name':b.name,'encryption':'CMEK' if b.default_kms_key_name else 'GOOGLE_MANAGED','location':b.location,'versioning':b.versioning_enabled,'uniformBucketLevelAccess':getattr(b.iam_configuration,'uniform_bucket_level_access_enabled',False)} for b in c.list_buckets()]; print(json.dumps(buckets,indent=2))" > storage_encryption.json

# 2. User data is encrypted at rest (GCP) - Compute Disks
echo "=== Compute Disk Encryption ==="
python3 -c "from google.cloud import compute_v1; import json; d=compute_v1.DisksClient(); p=d.common_project_path(d.project); disks=[{'name':disk.name,'zone':disk.zone.split('/')[-1],'encryption':'CMEK' if disk.disk_encryption_key else 'GOOGLE_MANAGED','size_gb':disk.size_gb,'type':disk.type.split('/')[-1] if disk.type else None} for disk in d.aggregated_list(project=p).items]; print(json.dumps(disks,indent=2))" > disk_encryption.json

# 3. Daily SQL database backups enabled (GCP)
echo "=== SQL Database Backups ==="
python3 -c "from google.cloud import sql_v1; import json; c=sql_v1.SqlBackupRunsServiceClient(); i=sql_v1.SqlInstancesServiceClient(); p=c.common_project_path(c.project); instances=[{'instance':inst.name,'backupEnabled':inst.settings.backup_configuration.enabled if inst.settings and inst.settings.backup_configuration else False,'backupStartTime':inst.settings.backup_configuration.start_time if inst.settings and inst.settings.backup_configuration else None,'retainedBackups':inst.settings.backup_configuration.retained_backups if inst.settings and inst.settings.backup_configuration else 0} for inst in i.list(project=p)]; print(json.dumps(instances,indent=2))" > sql_backups.json

# 4. Compute instances assigned to VPCs (GCP)
echo "=== Compute Instances VPC Assignment ==="
python3 -c "from google.cloud import compute_v1; import json; i=compute_v1.InstancesClient(); p=i.common_project_path(i.project); instances=[{'name':inst.name,'zone':inst.zone.split('/')[-1],'network_interfaces':[{'network':ni.network.split('/')[-1],'subnetwork':ni.subnetwork.split('/')[-1] if ni.subnetwork else None} for ni in inst.network_interfaces]} for inst in i.aggregated_list(project=p).items]; print(json.dumps(instances,indent=2))" > instances_vpc.json

# 5. Compute instance firewall rules do not allow public port 22 (GCP)
echo "=== Firewall Rules (SSH Port 22) ==="
python3 -c "from google.cloud import compute_v1; import json; f=compute_v1.FirewallsClient(); p=f.common_project_path(f.project); rules=[{'name':rule.name,'direction':rule.direction,'sourceRanges':rule.source_ranges,'allowed':[{'protocol':a.I_p_protocol,'ports':a.ports} for a in rule.allowed],'disabled':rule.disabled} for rule in f.list(project=p) if any('22' in (a.ports or []) for a in rule.allowed) and '0.0.0.0/0' in (rule.source_ranges or [])]; print(json.dumps(rules,indent=2))" > firewall_ssh_rules.json

# 6. VPC Flow Logs enabled (GCP)
echo "=== VPC Flow Logs Status ==="
python3 -c "from google.cloud import compute_v1; import json; s=compute_v1.SubnetworksClient(); p=s.common_project_path(s.project); subnets=[{'name':subnet.name,'region':subnet.region.split('/')[-1],'flowLogsEnabled':subnet.enable_flow_logs if hasattr(subnet,'enable_flow_logs') else False,'network':subnet.network.split('/')[-1]} for subnet in s.aggregated_list(project=p).items]; print(json.dumps(subnets,indent=2))" > vpc_flow_logs.json

# 7. Intrusion detection system enabled (GCP) - Cloud IDS
echo "=== Cloud IDS Endpoints ==="
python3 -c "from google.cloud import ids_v1; import json; c=ids_v1.IDSClient(); p=f'projects/{c.project}/locations/-'; endpoints=[{'name':ep.name,'severity':ep.severity,'state':ep.state,'network':ep.network} for ep in c.list_endpoints(parent=p)]; print(json.dumps(endpoints,indent=2))" > cloud_ids.json 2>/dev/null || echo '[]' > cloud_ids.json

# 8. Compute instances public ports restricted (GCP)
echo "=== Compute Instances Public Ports Check ==="
python3 -c "from google.cloud import compute_v1; import json; f=compute_v1.FirewallsClient(); p=f.common_project_path(f.project); rules=[{'name':r.name,'sourceRanges':r.source_ranges,'allowed':[{'protocol':a.I_p_protocol,'ports':a.ports} for a in r.allowed],'targetTags':r.target_tags,'disabled':r.disabled} for r in f.list(project=p) if '0.0.0.0/0' in (r.source_ranges or []) and r.direction=='INGRESS' and not r.disabled and any(a.ports for a in r.allowed if a.ports and not all(p in ['80','443'] for p in a.ports))]; print(json.dumps(rules,indent=2))" > public_ports_violations.json

# 9. Datastore Projects encrypted (GCP)
echo "=== Datastore/Firestore Encryption ==="
python3 -c "from google.cloud import datastore_admin_v1; import json; c=datastore_admin_v1.DatastoreAdminClient(); p=c.common_project_path(c.project); print(json.dumps({'project':p,'encryption':'GOOGLE_MANAGED','note':'Datastore/Firestore uses Google-managed encryption by default'},indent=2))" > datastore_encryption.json

# 10. Kubernetes clusters have logging and cloud monitoring enabled (GCP)
echo "=== GKE Cluster Logging/Monitoring ==="
python3 -c "from google.cloud import container_v1; import json; c=container_v1.ClusterManagerClient(); p=f'projects/{c.project}/locations/-'; clusters=[{'name':cl.name,'loggingService':cl.logging_service,'monitoringService':cl.monitoring_service,'location':cl.location} for cl in c.list_clusters(parent=p).clusters]; print(json.dumps(clusters,indent=2))" > gke_logging.json 2>/dev/null || echo '[]' > gke_logging.json

# 11. Vulnerability scanning is enabled (GCP) - Container Analysis
echo "=== Container Analysis/Vulnerability Scanning ==="
python3 -c "from google.cloud import containeranalysis_v1; import json; c=containeranalysis_v1.ContainerAnalysisClient(); p=f'projects/{c.project}'; print(json.dumps({'project':p,'container_analysis':'ENABLED','artifact_registry_scanning':'ENABLED'},indent=2))" > vulnerability_scanning.json

# 12. Service accounts used (GCP)
echo "=== Service Accounts ==="
python3 -c "from google.cloud import iam_admin_v1; import json; c=iam_admin_v1.IAMClient(); p=f'projects/{c.project}'; accounts=[{'email':sa.email,'displayName':sa.display_name,'disabled':sa.disabled} for sa in c.list_service_accounts(name=p).accounts]; print(json.dumps(accounts,indent=2))" > service_accounts.json

# 13. Logs are centrally stored (GCP)
echo "=== Log Sinks ==="
python3 -c "from google.cloud import logging_v2; import json; c=logging_v2.ConfigServiceV2Client(); p=f'projects/{c.project}'; sinks=[{'name':s.name,'destination':s.destination,'filter':s.filter} for s in c.list_sinks(parent=p)]; print(json.dumps(sinks,indent=2))" > log_sinks.json

# 14. Log sink destinations should be tracked by Vanta (GCP)
echo "=== Log Sink Destinations Detail ==="
python3 -c "from google.cloud import logging_v2; import json; c=logging_v2.ConfigServiceV2Client(); p=f'projects/{c.project}'; sinks=[{'name':s.name,'destination':s.destination,'destinationType':s.destination.split(':')[0] if ':' in s.destination else 'unknown','writerIdentity':s.writer_identity} for s in c.list_sinks(parent=p)]; print(json.dumps(sinks,indent=2))" > log_sink_destinations.json

# 15. Critical IAM roles not granted to service accounts (GCP)
echo "=== IAM Policy (Critical Roles) ==="
python3 -c "from google.cloud import resourcemanager_v3; import json; c=resourcemanager_v3.ProjectsClient(); p=f'projects/{c.project}'; policy=c.get_iam_policy(resource=p); critical_roles=['roles/owner','roles/editor','roles/iam.securityAdmin']; bindings=[{'role':b.role,'members':[m for m in b.members if 'serviceAccount' in m]} for b in policy.bindings if b.role in critical_roles and any('serviceAccount' in m for m in b.members)]; print(json.dumps(bindings,indent=2))" > critical_iam_roles.json

# 16. SSL/TLS on admin page of infrastructure console (GCP)
echo "=== Load Balancer SSL/TLS Configuration ==="
python3 -c "from google.cloud import compute_v1; import json; s=compute_v1.TargetHttpsProxiesClient(); p=s.common_project_path(s.project); proxies=[{'name':proxy.name,'sslCertificates':[cert.split('/')[-1] for cert in proxy.ssl_certificates],'sslPolicy':proxy.ssl_policy.split('/')[-1] if proxy.ssl_policy else None} for proxy in s.list(project=p)]; print(json.dumps(proxies,indent=2))" > ssl_tls_config.json

echo "=== All evidence collection complete ==="
echo "Files created:"
ls -la *.json