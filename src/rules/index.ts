import { SecurityRule, SecurityCategory, RuleType } from '../types';
import { authRules } from './authRules';
import { inputValidationRules } from './inputValidationRules';
import { csrfRules } from './csrfRules';
import { corsRules } from './corsRules';
import { encryptionRules } from './encryptionRules';
import { apiSecurityRules } from './apiSecurityRules';
import { databaseRules } from './databaseRules';
import { fileHandlingRules } from './fileHandlingRules';
import { secretsRules } from './secretsRules';
import { providerSecretsRules } from './providerSecretsRules';
import { ssrfRules } from './ssrfRules';
import { deserializationRules } from './deserializationRules';
import { sstiRules } from './sstiRules';
import { xxeRules } from './xxeRules';
import { jwtRules } from './jwtRules';
import { oauthRules } from './oauthRules';
import { ldapRules } from './ldapRules';
import { cmdInjectionRules } from './cmdInjectionRules';
import { frontendRules } from './frontendRules';
import { businessLogicRules } from './businessLogicRules';
import { loggingRules } from './loggingRules';
import { dependenciesRules } from './dependenciesRules';
import { infrastructureRules } from './infrastructureRules';
import {
  deployConfigInfraRules,
  deployConfigSecretsRules,
  deployConfigApiRules,
} from './deployConfigRules';
import { dockerfileRules } from './dockerfileRules';
import { terraformRules } from './terraformRules';
import { kubernetesRules } from './kubernetesRules';
import {
  kotlinAuthRules,
  kotlinXssRules,
  kotlinEncryptionRules,
  kotlinFileRules,
  kotlinDatabaseRules,
  kotlinLoggingRules,
  kotlinSecretsRules,
} from './kotlinAndroidRules';
import { securityHeadersRules } from './securityHeadersRules';

const allRulesByCategory: Record<SecurityCategory, SecurityRule[]> = {
  [SecurityCategory.AuthAccessControl]: [...authRules, ...jwtRules, ...oauthRules, ...ldapRules, ...kotlinAuthRules],
  [SecurityCategory.InputValidationXSS]: [
    ...inputValidationRules,
    ...deserializationRules,
    ...sstiRules,
    ...xxeRules,
    ...kotlinXssRules,
  ],
  [SecurityCategory.CSRFProtection]: csrfRules,
  [SecurityCategory.CORSConfiguration]: corsRules,
  [SecurityCategory.EncryptionDataProtection]: [...encryptionRules, ...kotlinEncryptionRules],
  [SecurityCategory.APISecurity]: [...apiSecurityRules, ...ssrfRules, ...cmdInjectionRules, ...deployConfigApiRules],
  [SecurityCategory.DatabaseSecurity]: [...databaseRules, ...kotlinDatabaseRules],
  [SecurityCategory.FileHandling]: [...fileHandlingRules, ...kotlinFileRules],
  [SecurityCategory.SecretsCredentials]: [...secretsRules, ...providerSecretsRules, ...kotlinSecretsRules, ...deployConfigSecretsRules],
  [SecurityCategory.FrontendSecurity]: frontendRules,
  [SecurityCategory.BusinessLogicPayment]: businessLogicRules,
  [SecurityCategory.LoggingMonitoring]: [...loggingRules, ...kotlinLoggingRules],
  [SecurityCategory.DependenciesSupplyChain]: dependenciesRules,
  [SecurityCategory.InfrastructureDeployment]: [
    ...infrastructureRules,
    ...securityHeadersRules,
    ...dockerfileRules,
    ...terraformRules,
    ...kubernetesRules,
    ...deployConfigInfraRules,
  ],
};

/**
 * Rules that must keep matching inside comments even though they are
 * Informational. A credential pasted into a comment is still a leaked
 * credential, so secret-VALUE detectors are exempt from the blanket
 * comment suppression below. (Reminder-style rules that merely mention a
 * filename — e.g. CRED007 "is .env in .gitignore?" — are not exempt:
 * matching the word `.env` inside prose is pure noise.)
 */
const SECRET_VALUE_RULE = /^(?:TOKEN|KT-CRED)/;

/**
 * Informational rules are advisory nudges about code that actually runs,
 * so a match inside a comment is never actionable. Self-scanning Caspian's
 * own source surfaced this: HDR005, API010 and CRED007 all fired on
 * explanatory prose in code comments.
 *
 * Applied here, at the registry, rather than on ~65 individual rule
 * definitions — so new Informational rules inherit it automatically.
 * `skipComments` (unlike `contextAware`) leaves string literals matchable.
 */
function applyDefaultCommentSuppression(rules: SecurityRule[]): SecurityRule[] {
  return rules.map(rule => {
    if (rule.ruleType !== RuleType.Informational) { return rule; }
    if (rule.contextAware || rule.skipComments) { return rule; }
    if (SECRET_VALUE_RULE.test(rule.code)) { return rule; }
    return { ...rule, skipComments: true };
  });
}

const resolvedRulesByCategory: Record<SecurityCategory, SecurityRule[]> =
  Object.fromEntries(
    Object.entries(allRulesByCategory).map(([cat, rules]) => [
      cat,
      applyDefaultCommentSuppression(rules),
    ])
  ) as Record<SecurityCategory, SecurityRule[]>;

export function getAllRules(): SecurityRule[] {
  return Object.values(resolvedRulesByCategory).flat();
}

export function getRulesByCategory(category: SecurityCategory): SecurityRule[] {
  return resolvedRulesByCategory[category] || [];
}

export function getRuleByCode(code: string): SecurityRule | undefined {
  return getAllRules().find(r => r.code === code);
}

export function getCategories(): SecurityCategory[] {
  return Object.values(SecurityCategory);
}
