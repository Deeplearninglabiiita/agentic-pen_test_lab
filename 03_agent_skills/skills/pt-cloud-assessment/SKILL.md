---
name: pt-cloud-assessment
description: >
  Assesses cloud infrastructure security across AWS, Azure, and GCP.
Use when evaluating S3 bucket permissions, IAM misconfigurations, exposed metadata endpoints,
or testing cloud-native application security. Activates on: cloud security, S3 bucket,
IAM assessment, metadata endpoint, cloud misconfiguration.
---

# Cloud Infrastructure Security Assessment

## Authorization (mandatory)
- Confirm cloud account is in scope and testing is authorized in writing
- Confirm no production workloads will be disrupted
- Identify emergency rollback contact before starting

## Objectives
1. Enumerate exposed cloud storage (S3, Azure Blob, GCS)
2. Identify IAM misconfigurations and privilege escalation paths
3. Check metadata endpoint exposure (SSRF to 169.254.169.254)
4. Assess network security groups and firewall rules
5. Check for secrets in environment variables and config files

## Workflow

### Phase 1: Passive enumeration
- Check for public S3 buckets via bucket name guessing
- Query certificate transparency for cloud subdomains
- Search Shodan for cloud metadata endpoints

### Phase 2: IAM assessment
- Enumerate attached policies
- Check for wildcard permissions (Action: *)
- Identify service accounts with excessive permissions

### Phase 3: Metadata endpoint testing
- Test /api/fetch?url=http://169.254.169.254/latest/meta-data/
- Check for IMDSv2 enforcement
- Attempt credential extraction from metadata

## Output template

CLOUD ASSESSMENT FINDINGS
Account: [id] | Region: [region] | Tester: [name]

EXPOSED STORAGE
[bucket] | [permissions] | [sensitive data found]

IAM MISCONFIGURATIONS
[policy] | [excessive permission] | [escalation path]

METADATA ENDPOINT
[endpoint tested] | [IMDSv2 enforced: yes/no] | [credentials exposed: yes/no]

REMEDIATION PRIORITY
Critical: [list]
High: [list]

## Quality checks
- [ ] Authorization confirmed
- [ ] No production disruption
- [ ] All findings have evidence
- [ ] Remediation guidance specific to cloud provider
