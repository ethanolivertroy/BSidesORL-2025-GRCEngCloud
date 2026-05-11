# GCP Service Account Setup

## Prerequisites
- GCP Project with billing enabled
- Owner or Project IAM Admin permissions
- Google Cloud SDK installed and authenticated

## Step 1: Create the Service Account

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID

# Create the service account
gcloud iam service-accounts create gcp-audit-evaluator \
    --display-name="GCP Audit Evaluator" \
    --description="Read-only service account for running audit scripts"
```

## Step 2: Assign Required IAM Roles

```bash
# Get the service account email
export SA_EMAIL="gcp-audit-evaluator@${PROJECT_ID}.iam.gserviceaccount.com"

# Assign core read-only roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/viewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/iam.securityReviewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/cloudasset.viewer"

# Optional: Security Command Center findings
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/securitycenter.findingsViewer"

# Optional: Recommender output
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/recommender.viewer"
```

## Step 3: Generate the Service Account Key

```bash
# Create the JSON key file
gcloud iam service-accounts keys create ~/gcp-audit-key.json \
    --iam-account=$SA_EMAIL

# Secure the key file
chmod 600 ~/gcp-audit-key.json
```

## Step 4: Point the Collector at the Key

```bash
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/gcp-audit-key.json"
```

## Step 5: Verify Access

Test that the service account can read the project:

```bash
# Test basic project access
gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
gcloud projects describe $PROJECT_ID

# Test resource listing
gcloud compute instances list
gcloud storage buckets list
gcloud iam service-accounts list
```

## For Multi-Project Assessments

### Option 1: Multiple Individual Projects

If you need specific projects without organization-level access:

```bash
# Set your service account email
export SA_EMAIL="gcp-audit-evaluator@${PROJECT_ID}.iam.gserviceaccount.com"

# Projects to assess
PROJECTS="project-1 project-2 project-3"

# Grant access to each project
for PROJECT in $PROJECTS; do
    echo "Granting access to $PROJECT..."
    
    gcloud projects add-iam-policy-binding $PROJECT \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/viewer"
    
    gcloud projects add-iam-policy-binding $PROJECT \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/iam.securityReviewer"
done
```

### Option 2: Organization-Level Access

If you need all projects under an organization:

```bash
# Get your organization ID
gcloud organizations list

# Set organization ID
export ORG_ID="your-org-id"

# Assign organization-level roles
gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/resourcemanager.organizationViewer"

gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/resourcemanager.folderViewer"

# For billing information access
gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/billing.viewer"
```

## Security Notes

1. Store the JSON key securely. Do not commit it.
2. Add roles only when the collector needs them.
3. Rotate keys if this becomes a standing process.
4. Watch service account usage in Cloud Audit Logs.

## Cleanup (When Done)

```bash
# Delete the service account key
gcloud iam service-accounts keys delete KEY_ID \
    --iam-account=$SA_EMAIL

# Delete the service account
gcloud iam service-accounts delete $SA_EMAIL
```

## Running Multi-Project Collection

Once the service account can read multiple projects:

```bash
# Set authentication
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/gcp-audit-key.json"

# Option 1: Specify projects directly
python3 gcp_fedramp20x_collector_multi.py --projects project-1,project-2,project-3

# Option 2: Use a project file
cat > projects.txt << EOF
project-1
project-2
project-3
EOF

python3 gcp_fedramp20x_collector_multi.py --project-file projects.txt

# Option 3: Run in parallel
python3 gcp_fedramp20x_collector_multi.py --project-file projects.txt --parallel
```

The multi-project collector:
- Creates individual archives for each project
- Keeps going if one project fails
- Writes a summary report of all collections
- Saves everything in a timestamped directory

## Troubleshooting

**Permission denied**: confirm you can create service accounts and assign IAM roles.

**API not enabled**: some checks need extra APIs:
```bash
# Core APIs
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable iam.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
gcloud services enable cloudasset.googleapis.com
gcloud services enable securitycenter.googleapis.com
gcloud services enable cloudkms.googleapis.com

# Extra APIs for deeper checks
gcloud services enable cloudbuild.googleapis.com
gcloud services enable binaryauthorization.googleapis.com
gcloud services enable containeranalysis.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable networkservices.googleapis.com
gcloud services enable accessapproval.googleapis.com
gcloud services enable essentialcontacts.googleapis.com
gcloud services enable backupdr.googleapis.com
gcloud services enable osconfig.googleapis.com
gcloud services enable monitoring.googleapis.com
gcloud services enable logging.googleapis.com
```

At that point, the service account should have read-only access for the collector.
