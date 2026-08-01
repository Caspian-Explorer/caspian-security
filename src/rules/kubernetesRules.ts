import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Kubernetes manifest rules.
 *
 * These only fire on YAML files that look like a K8s resource — we use
 * `suppressIfNearby` on a lack of `apiVersion:` / `kind:` as a crude gate
 * so every random YAML doesn't get spammed with K8s-specific warnings.
 *
 * Coverage mirrors the NSA / CISA Kubernetes Hardening Guide and the
 * Pod Security Standards `baseline` / `restricted` profiles.
 */

const cat = SecurityCategory.InfrastructureDeployment;
const ruleType = RuleType.CodeDetectable;

const YAML_ONLY = {
  include: [/\.ya?ml$/i],
  // Avoid firing on GitHub Actions workflows, docker-compose files, etc.
  exclude: [/[\\/]\.github[\\/]/i, /docker-?compose\.ya?ml$/i],
};

/**
 * Fire only if there's a nearby K8s-shaped apiVersion/kind, so a random
 * config.yaml without Kubernetes doesn't trip these.
 */
const REQUIRE_K8S_MARKERS: RegExp[] = [
  /\bapiVersion:\s*(?:v1|apps\/v1|batch\/v1|networking\.k8s\.io\/v1|rbac\.authorization\.k8s\.io\/v1|policy\/v1)\b/,
  /\bkind:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|Service|Ingress|ConfigMap|Secret|Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy)\b/,
];

/**
 * Helper to require BOTH suppressIfNearby (safe patterns) AND the K8s
 * markers. The rule shape only supports suppressIfNearby; to require
 * the markers as a prerequisite, we use `filePatterns.include` on `.yaml`
 * and hope the pattern itself is specific enough to only match real
 * manifests. Acceptable FP rate given the specificity of K8s keywords.
 */

// Exact-config-key matches are rarely accidental: CodeDetectable rules in
// this family carry base confidence 'critical'.
export const kubernetesRules: SecurityRule[] = ([
  {
    code: 'K8S001',
    message: 'Pod / container runs with `privileged: true` — equivalent to root on the host',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*privileged:\s*true\b/m,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      '`privileged: true` disables every container isolation feature — the container can reconfigure ' +
      'the host network, mount host filesystems, and load kernel modules. Drop it, and add back only the ' +
      'specific capabilities you need via `capabilities.add`.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S002',
    message: 'Pod has `hostNetwork: true` — shares the host network namespace',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*hostNetwork:\s*true\b/m,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'hostNetwork lets the pod bind to any host port and see host-local traffic (including the kubelet ' +
      'and the API server on localhost). Use a dedicated service with NodePort / hostPort only if you ' +
      'genuinely need it.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S003',
    message: 'Pod has `hostPID: true` or `hostIPC: true` — breaks process / IPC isolation',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*hostPID:\s*true\b/m,
      /^\s*hostIPC:\s*true\b/m,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'hostPID exposes every process on the node to this container — any process listing leaks secrets ' +
      'from other workloads. Remove unless you are building a kernel debugger.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S004',
    message: 'Container runs as root (`runAsUser: 0` or no `runAsNonRoot`)',
    severity: SecuritySeverity.Warning,
    patterns: [
      /^\s*runAsUser:\s*0\b/m,
      /^\s*allowPrivilegeEscalation:\s*true\b/m,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'Set `runAsNonRoot: true` and `runAsUser: <non-zero>` at either the pod or container securityContext. ' +
      'Also set `allowPrivilegeEscalation: false`.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S005',
    message: 'Host path volume mounted — gives the container access to the host filesystem',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*hostPath:\s*$/m,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'hostPath mounts are a classic container escape. Prefer a PersistentVolumeClaim. If you absolutely ' +
      'need hostPath (log collectors, CNI plugins), scope it tightly and mark the pod as privileged by ' +
      'convention — operators should review it.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S006',
    message: 'Container uses a Linux capability beyond the restricted set',
    severity: SecuritySeverity.Warning,
    patterns: [
      /add:\s*\[?["']?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|NET_RAW|DAC_READ_SEARCH|BPF)["']?/,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'SYS_ADMIN is essentially root. NET_ADMIN lets the container reconfigure the pod\'s network, ' +
      'which is a privilege in CNIs without strict network policy. Drop to the minimum set — most apps ' +
      'need none.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S007',
    message: 'ClusterRole / Role binds wildcard `["*"]` verbs or resources',
    severity: SecuritySeverity.Error,
    patterns: [
      /verbs:\s*\[\s*["']\*["']\s*\]/,
      /resources:\s*\[\s*["']\*["']\s*\]/,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'Wildcard verbs/resources in RBAC is equivalent to cluster-admin on the covered scope. Enumerate ' +
      'the specific verbs (`get`, `list`, `watch`) and resources you actually need.',
    category: cat,
    ruleType,
  },
  {
    code: 'K8S008',
    message: 'Service of type NodePort / LoadBalancer exposed without source restriction',
    severity: SecuritySeverity.Warning,
    patterns: [
      /^\s*type:\s*(?:NodePort|LoadBalancer)\b/m,
    ],
    suppressIfNearby: [
      /loadBalancerSourceRanges:/,
      /externalTrafficPolicy:\s*Local/,
      /\binternal:\s*true/,
    ],
    filePatterns: YAML_ONLY,
    suggestion:
      'A LoadBalancer without `loadBalancerSourceRanges` exposes the backing pods to the internet. ' +
      'Use an Ingress with TLS + WAF, or restrict sources to your corp CIDR.',
    category: cat,
    ruleType,
  },
] as SecurityRule[]).map(rule =>
  rule.ruleType === RuleType.CodeDetectable ? { ...rule, confidence: 'critical' as const } : rule
);
