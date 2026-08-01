import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Terraform / HCL rules.
 *
 * Only the highest-signal patterns — the ones that show up in real
 * public-exposure incidents. Each rule is tied to a specific resource
 * kind (security group, S3 bucket, IAM policy, RDS, Lambda) so the
 * suggestion can be concrete.
 *
 * Style note: we match on the HCL assignment syntax (`= "value"`,
 * `= ["..."]`, block form `{ ... }`) rather than trying to parse the
 * graph. Bounded quantifiers throughout — the ReDoS guard passes.
 */

const cat = SecurityCategory.InfrastructureDeployment;
const ruleType = RuleType.CodeDetectable;

const TERRAFORM_ONLY = {
  include: [/\.tf(vars)?$/i, /\.hcl$/i],
};

// Exact-config-key matches are rarely accidental: CodeDetectable rules in
// this family carry base confidence 'critical'.
export const terraformRules: SecurityRule[] = ([
  {
    code: 'TF001',
    message: 'Security group allows ingress from 0.0.0.0/0 — exposed to the entire internet',
    severity: SecuritySeverity.Error,
    patterns: [
      /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/,
      /source_security_group_id\s*=\s*["']sg-[0-9a-f]+["']\s*#\s*(?:public|internet)/i,
      /ipv6_cidr_blocks\s*=\s*\[\s*["']::\/0["']/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      '0.0.0.0/0 ingress is only ever correct for public-facing HTTP(S) load balancers on port 80/443. ' +
      'Restrict to your corp VPN CIDR, an allow-list of S2S peers, or the VPC CIDR itself. For SSH / ' +
      'admin ports, always use a bastion + session-manager.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF002',
    message: 'S3 bucket ACL set to public — readable or writable by the world',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bacl\s*=\s*["'](?:public-read|public-read-write|authenticated-read)["']/,
      /\bblock_public_acls\s*=\s*false/,
      /\bblock_public_policy\s*=\s*false/,
      /\bignore_public_acls\s*=\s*false/,
      /\brestrict_public_buckets\s*=\s*false/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Keep every public-access block set to `true` and the ACL `"private"`. If the bucket must be ' +
      'public (static site, public downloads), use CloudFront + OAI / OAC in front of a still-private ' +
      'bucket rather than opening the bucket itself.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF003',
    message: 'IAM policy grants wildcard Action `*` or Resource `*`',
    severity: SecuritySeverity.Error,
    patterns: [
      // Terraform HCL — aws_iam_policy_document uses lowercase plural `actions` / `resources`.
      /\bactions\s*=\s*\[[^\]]*["']\*["']/i,
      /\bresources\s*=\s*\[[^\]]*["']\*["']/i,
      // IAM JSON policy form — `"Action": "*"` or `"Action": ["*", ...]`.
      /"Action"\s*:\s*(?:\[\s*)?"\*"/,
      /"Resource"\s*:\s*(?:\[\s*)?"\*"/,
      // Singular HCL form — `action = "*"` (older style).
      /\baction\s*=\s*["']\*["']/i,
      /\bresource\s*=\s*["']\*["']/i,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Replace wildcards with explicit action lists (`s3:GetObject`, `s3:PutObject`) and resource ARNs. ' +
      'For admin principals, scope to specific roles and require MFA / session tags. Use IAM Access ' +
      'Analyzer to identify the minimum set.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF004',
    message: 'RDS / Aurora instance has `publicly_accessible = true`',
    severity: SecuritySeverity.Error,
    patterns: [
      /publicly_accessible\s*=\s*true/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Databases should live in private subnets only. Access them via VPN, SSM Session Manager, or a ' +
      'bastion. If you have a genuine need for direct internet access, at minimum restrict the security ' +
      'group to specific client CIDRs and enable IAM auth.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF005',
    message: 'Storage resource has no encryption_at_rest / server_side_encryption configured',
    severity: SecuritySeverity.Warning,
    // Matching is line-scoped, so a lookahead across the resource body can
    // never see the attributes; suppress via the nearby-lines window
    // instead. The aws_s3_bucket pattern was dropped entirely: since AWS
    // provider v4 the SSE config is a separate resource type, and S3
    // buckets are encrypted at rest by default (Jan 2023) — flagging every
    // bucket declaration was pure noise.
    patterns: [
      /\bresource\s+["']aws_ebs_volume["']/,
      /\bresource\s+["']aws_db_instance["']/,
    ],
    suppressIfNearby: [
      /\bencrypted\s*=\s*true\b/,
      /\bstorage_encrypted\s*=\s*true\b/,
    ],
    suppressNearbyWindow: 15,
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Every at-rest store should be encrypted. Enable `server_side_encryption_configuration` on S3, ' +
      '`encrypted = true` on EBS, and `storage_encrypted = true` on RDS. Prefer customer-managed KMS ' +
      'keys so you can rotate and audit usage.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF006',
    message: 'Hardcoded password / secret in a Terraform resource',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:master_)?password\s*=\s*["'][^"']{4,}["']/i,
    ],
    negativePatterns: [
      /var\.|local\.|data\.aws_secretsmanager_|random_password\./,
      /sensitive\s*=\s*true/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Never commit a plaintext credential to .tf / .tfvars. Use `aws_secretsmanager_secret` + ' +
      '`data.aws_secretsmanager_secret_version`, or generate with `random_password` + manage_master_user_password.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF007',
    message: 'CloudTrail / logging resource with logging disabled',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\blogging\s*\{[^}]*enabled\s*=\s*false/,
      /\bflow_log.*\bLogDestination\s*=\s*(?:null|""|''\s*)/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'You will only learn about a breach from logs. Keep CloudTrail on in every region, flow logs on ' +
      'in every VPC, and S3 access logging on every sensitive bucket.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF008',
    message: 'Lambda / ECS task role attached to managed admin policy',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bpolicy_arn\s*=\s*["']arn:aws:iam::aws:policy\/AdministratorAccess["']/,
      /\bmanaged_policy_arns\s*=\s*\[[^\]]*AdministratorAccess/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'A compromised task / function with AdministratorAccess owns your entire AWS account. Define a ' +
      'least-privilege inline policy specific to the resources this function touches.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF009',
    message: 'ELB / ALB listener configured for plain HTTP without redirect to HTTPS',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bprotocol\s*=\s*["']HTTP["']\s*(?![\s\S]{0,300}default_action\s*\{[\s\S]*?redirect)/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Keep an HTTP listener on port 80 only to redirect to HTTPS. Otherwise auth cookies and API tokens ' +
      'traverse the internet in cleartext.',
    category: cat,
    ruleType,
  },
  {
    code: 'TF010',
    message: 'KMS key policy allows `kms:*` to the full AWS account root',
    severity: SecuritySeverity.Warning,
    patterns: [
      /"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"arn:aws:iam::\d+:root"\s*\}\s*,\s*"Action"\s*:\s*"kms:\*"/,
      /Principal\s*=\s*\{\s*AWS\s*=\s*"arn:aws:iam::\d+:root"\s*\}\s*\n\s*Action\s*=\s*"kms:\*"/,
    ],
    filePatterns: TERRAFORM_ONLY,
    suggestion:
      'Delegating `kms:*` to the account root means any IAM principal with kms permissions can use the ' +
      'key — defeating the KMS allow-list model. Restrict to specific administrator roles.',
    category: cat,
    ruleType,
  },
] as SecurityRule[]).map(rule =>
  rule.ruleType === RuleType.CodeDetectable ? { ...rule, confidence: 'critical' as const } : rule
);
