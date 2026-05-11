# GCP Permissions Reference

## Minimum Required Permissions

This lists the GCP permissions the collector may need.

### Option 1: Predefined Roles

Assign these roles to the user or service account:

```
roles/viewer                    # Basic read access to all resources
roles/iam.securityReviewer     # Read access to IAM policies
```

### Option 2: Custom Role

Create a read-only custom role:

```yaml
title: "FedRAMP Assessment Reader"
description: "Read-only access for FedRAMP compliance assessment"
stage: "GA"
includedPermissions:
  # IAM & Organization
  - iam.roles.list
  - iam.roles.get
  - iam.serviceAccounts.list
  - iam.serviceAccounts.get
  - iam.serviceAccountKeys.list
  - resourcemanager.projects.get
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.organizations.get
  - orgpolicy.policies.list
  
  # Compute Engine
  - compute.instances.list
  - compute.instances.get
  - compute.disks.list
  - compute.disks.get
  - compute.firewalls.list
  - compute.firewalls.get
  - compute.networks.list
  - compute.networks.get
  - compute.subnetworks.list
  - compute.subnetworks.get
  - compute.routes.list
  - compute.routes.get
  - compute.routers.list
  - compute.routers.get
  - compute.snapshots.list
  - compute.images.list
  - compute.machineImages.list
  - compute.instanceTemplates.list
  - compute.instanceGroups.list
  - compute.zones.list
  - compute.regions.list
  - compute.sslCertificates.list
  - compute.targetHttpProxies.list
  - compute.targetHttpsProxies.list
  - compute.urlMaps.list
  - compute.backendServices.list
  - compute.healthChecks.list
  - compute.vpnTunnels.list
  - compute.vpnGateways.list
  - osconfig.patchDeployments.list
  - osconfig.patchJobs.list
  
  # Storage
  - storage.buckets.list
  - storage.buckets.get
  - storage.buckets.getIamPolicy
  
  # Cloud KMS
  - cloudkms.keyRings.list
  - cloudkms.cryptoKeys.list
  - cloudkms.cryptoKeys.get
  
  # Logging & Monitoring
  - logging.logs.list
  - logging.sinks.list
  - logging.metrics.list
  - logging.entries.list
  - monitoring.alertPolicies.list
  - monitoring.dashboards.list
  - monitoring.uptimeCheckConfigs.list
  
  # Networking & Security
  - compute.securityPolicies.list
  - servicenetworking.services.list
  - accesscontextmanager.accessPolicies.list
  - accesscontextmanager.servicePerimeters.list
  
  # Databases
  - cloudsql.instances.list
  - cloudsql.instances.get
  - cloudsql.databases.list
  - spanner.instances.list
  - spanner.databases.list
  - bigtable.instances.list
  - redis.instances.list
  - firebasedatabase.instances.list
  
  # Containers & Serverless
  - container.clusters.list
  - container.clusters.get
  - cloudfunctions.functions.list
  - run.services.list
  - appengine.services.list
  - appengine.versions.list
  - artifactregistry.repositories.list
  
  # Big Data & Analytics
  - pubsub.topics.list
  - pubsub.topics.get
  - pubsub.subscriptions.list
  - dataflow.jobs.list
  - dataproc.clusters.list
  - bigquery.datasets.list
  - composer.environments.list
  
  # AI/ML
  - ml.models.list
  - notebooks.instances.list
  - aiplatform.endpoints.list
  
  # Security & Compliance
  - securitycenter.findings.list
  - securitycenter.sources.list
  - securitycenter.organizationSettings.get
  - secretmanager.secrets.list
  - secretmanager.secrets.get
  - privateca.caPools.list
  
  # Asset Management
  - cloudasset.assets.searchAllResources
  - cloudasset.assets.searchAllIamPolicies
  
  # Other services
  - deploymentmanager.deployments.list
  - source.repos.list
  - eventarc.triggers.list
  - serviceusage.services.list
  - serviceusage.services.get
  
  # Cloud Build
  - cloudbuild.builds.list
  - cloudbuild.triggers.list
  
  # Binary Authorization
  - binaryauthorization.policy.get
  - binaryauthorization.attestors.list
  
  # Container Analysis
  - containeranalysis.occurrences.list
  
  # Firestore
  - datastore.databases.list
  
  # Network Services
  - networkservices.grpcRoutes.list
  
  # Access Approval
  - accessapproval.settings.get
  - accessapproval.requests.list
  
  # Essential Contacts
  - essentialcontacts.contacts.list
  
  # Backup and DR
  - backupdr.backupPlans.list
  - backupdr.backupVaults.list
  
  # Additional Compute Permissions
  - compute.forwardingRules.list
  - compute.networkEndpointGroups.list
  - compute.serviceAttachments.list
  - compute.firewallPolicies.list
  - compute.projects.get
  - compute.projects.getXpnResources
  - compute.projects.getXpnHost
  
  # Additional Cloud Resource Manager
  - cloudresourcemanager.folders.get
  - cloudresourcemanager.folders.getIamPolicy
  - cloudresourcemanager.organizations.search
  - cloudresourcemanager.projects.getEffectiveOrgPolicy
  
  # Additional Monitoring
  - monitoring.notificationChannels.list
  
  # Additional OS Config
  - osconfig.inventories.get
  
  # Additional IAM
  - iam.workloadIdentityPools.list
  - iam.workloadIdentityPoolProviders.list
  
  # Additional Logging
  - logging.views.list
```

### Option 3: Using gcloud to Create Custom Role

```bash
# Create a JSON file with the permissions
cat > fedramp-reader-role.json << 'EOF'
{
  "title": "FedRAMP Assessment Reader",
  "description": "Read-only access for FedRAMP compliance assessment",
  "stage": "GA",
  "includedPermissions": [
    "iam.roles.list",
    "iam.serviceAccounts.list",
    "compute.instances.list",
    "compute.disks.list",
    "compute.firewalls.list",
    "storage.buckets.list",
    "storage.buckets.get",
    "logging.sinks.list",
    "monitoring.alertPolicies.list"
    # ... add all permissions from above
  ]
}
EOF

# Create the custom role
gcloud iam roles create fedRampAssessmentReader \
    --project=YOUR_PROJECT_ID \
    --file=fedramp-reader-role.json

# Grant the role to a user
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="user:assessor@example.com" \
    --role="projects/YOUR_PROJECT_ID/roles/fedRampAssessmentReader"
```

## Service Account Setup

```bash
# Create service account
gcloud iam service-accounts create fedramp-assessment \
    --display-name="FedRAMP Assessment Reader"

# Grant roles
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:fedramp-assessment@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/viewer"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:fedramp-assessment@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/iam.securityReviewer"

# Create a key
gcloud iam service-accounts keys create ~/fedramp-key.json \
    --iam-account=fedramp-assessment@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

## Verification

To verify permissions:

```bash
# Check current user's permissions
gcloud projects get-iam-policy YOUR_PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:YOUR_EMAIL"

# Test access
gcloud auth list
gcloud compute instances list --limit=1
gcloud storage buckets list --limit=1
```

## Troubleshooting

If you see "Permission Denied" errors:

1. **Check enabled APIs**
   ```bash
   gcloud services list --enabled
   ```

2. **Verify role assignment**
   ```bash
   gcloud projects get-iam-policy YOUR_PROJECT_ID
   ```

3. **Common Missing APIs**
   - Cloud Resource Manager API
   - Cloud Asset API
   - Security Command Center API
   - Cloud KMS API
   - Cloud Build API
   - Binary Authorization API
   - Container Analysis API
   - Firestore API
   - Network Services API
   - Access Approval API
   - Essential Contacts API
   - Backup and DR API

4. **Enable Required APIs**
   ```bash
   # Core APIs
   gcloud services enable cloudresourcemanager.googleapis.com
   gcloud services enable cloudasset.googleapis.com
   gcloud services enable securitycenter.googleapis.com
   gcloud services enable cloudkms.googleapis.com
   
   # Additional APIs
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable binaryauthorization.googleapis.com
   gcloud services enable containeranalysis.googleapis.com
   gcloud services enable firestore.googleapis.com
   gcloud services enable networkservices.googleapis.com
   gcloud services enable accessapproval.googleapis.com
   gcloud services enable essentialcontacts.googleapis.com
   gcloud services enable backupdr.googleapis.com
   ```

## Security Notes

1. Use service accounts instead of personal accounts.
2. Grant only the permissions you need.
3. Use temporary access when possible.
4. Review who has assessment access.
5. Delete the service account when the assessment is done.

## Notes

- Some commands may fail if the corresponding service isn't enabled
- Organization-level commands require organization-level permissions
- The script records permission errors and keeps going
- No write permissions are needed or requested
