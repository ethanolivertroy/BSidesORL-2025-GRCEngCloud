#!/usr/bin/env python3
"""
Standalone script to collect GCP storage bucket encryption data
"""

import json
import concurrent.futures
from google.cloud import storage

def collect_storage_encryption():
    """Collect storage bucket encryption status with lifecycle and versioning"""
    print("Checking bucket encryption, lifecycle, and versioning...")
    buckets_info = []
    
    storage_client = storage.Client()
    
    try:
        buckets = list(storage_client.list_buckets())
        
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
            info['logging'] = {
                'logBucket': bucket.logging.get('logBucket') if bucket.logging else None,
                'logObjectPrefix': bucket.logging.get('logObjectPrefix') if bucket.logging else None
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
            
    except Exception as e:
        print(f"Error collecting storage encryption: {e}")
        return []
    
    print(f"Collected data for {len(buckets_info)} buckets")
    return buckets_info

if __name__ == "__main__":
    # Collect the data
    data = collect_storage_encryption()
    
    # Save to JSON file
    with open('all_buckets_encryption.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved to all_buckets_encryption.json")