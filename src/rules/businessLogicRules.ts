import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const businessLogicRules: SecurityRule[] = [
  {
    code: 'BIZ001',
    message: 'Premium/paid feature check may be client-side only',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:isPremium|isPro|isSubscribed|hasPlan|planType)\s*(?:&&|\?)/i,
      /(?:premium|subscription|plan)\s*[:=]\s*(?:true|false)/i,
    ],
    suggestion: 'Enforce premium/subscription checks SERVER-SIDE; never trust client-side feature flags for paid features',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
    filePatterns: {
      reduceSeverityIn: [/\.tsx$/i, /\.jsx$/i, /components?\//i, /pages?\//i, /views?\//i, /hooks?\//i],
    },
  },
  {
    code: 'BIZ002',
    message: 'Reminder: Verify payment success server-side before unlocking features',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:payment|checkout).*(?:success|complete|confirmed)/i,
      /(?:onSuccess|onApprove|paymentIntent).*(?:status|result)/i,
    ],
    suggestion: 'Verify payment success via server-side webhook (e.g., Stripe webhook) before granting access; never rely on client-side payment callbacks alone',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ003',
    message: 'Refund logic may allow duplicate refunds',
    severity: SecuritySeverity.Warning,
    patterns: [
      /refund/i,
    ],
    suggestion: 'Implement idempotency checks for refund operations; track refund status to prevent duplicate refunds',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ004',
    message: 'Trial period logic detected — ensure it cannot be exploited',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:trial|freeTrial|free_trial|trialEnd|trial_end)/i,
      /trialPeriod/i,
    ],
    suggestion: 'Enforce trial limits server-side; prevent trial reuse via account re-creation (tie trials to payment method, device, or email domain)',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ005',
    message: 'Reminder: Revoke feature access immediately on subscription cancellation',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:cancel|unsubscribe).*(?:subscription|plan|membership)/i,
      /(?:subscription|plan|membership).*(?:cancel|unsubscribe)/i,
    ],
    suggestion: 'Revoke premium feature access on subscription cancel/expiry; handle via payment processor webhooks (e.g., customer.subscription.deleted)',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ006',
    message: 'Reminder: Keep subscription state synced with payment processor',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:stripe|paypal|paddle|braintree|chargebee)/i,
    ],
    suggestion: 'Sync subscription state via webhooks from your payment processor; never rely solely on local database state for billing decisions',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ007',
    message: 'Quota or usage limit may be enforced client-side only',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:quota|usage|limit|remaining).*(?:count|check|enforce|exceeded)/i,
      /(?:count|check|enforce|exceeded).*(?:quota|usage|limit|remaining)/i,
    ],
    suggestion: 'Enforce quotas and usage limits SERVER-SIDE; do not trust client-reported usage counts',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'BIZ008',
    message: 'Usage tracking may rely on client-reported data',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:req|request)\.(?:body|query|params)\.(?:count|usage|consumed|used)/i,
    ],
    suggestion: 'Track usage server-side using metered counters; never accept client-reported usage values for billing or quota enforcement',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'BIZ009',
    message: 'Reminder: Ensure quota resets occur at the correct time server-side',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:reset|renew).*(?:quota|usage|limit|allowance)/i,
      /(?:quota|usage|limit|allowance).*(?:reset|renew)/i,
    ],
    suggestion: 'Schedule quota resets server-side using cron jobs or payment processor billing cycle events; verify reset timing is correct',
    category: SecurityCategory.BusinessLogicPayment,
    ruleType: RuleType.Informational,
  },
];
