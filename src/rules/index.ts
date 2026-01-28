import { SecurityRule, SecurityCategory } from '../types';
import { authRules } from './authRules';
import { inputValidationRules } from './inputValidationRules';
import { csrfRules } from './csrfRules';
import { corsRules } from './corsRules';
import { encryptionRules } from './encryptionRules';
import { apiSecurityRules } from './apiSecurityRules';
import { databaseRules } from './databaseRules';
import { fileHandlingRules } from './fileHandlingRules';
import { secretsRules } from './secretsRules';
import { frontendRules } from './frontendRules';
import { businessLogicRules } from './businessLogicRules';
import { loggingRules } from './loggingRules';

const allRulesByCategory: Record<SecurityCategory, SecurityRule[]> = {
  [SecurityCategory.AuthAccessControl]: authRules,
  [SecurityCategory.InputValidationXSS]: inputValidationRules,
  [SecurityCategory.CSRFProtection]: csrfRules,
  [SecurityCategory.CORSConfiguration]: corsRules,
  [SecurityCategory.EncryptionDataProtection]: encryptionRules,
  [SecurityCategory.APISecurity]: apiSecurityRules,
  [SecurityCategory.DatabaseSecurity]: databaseRules,
  [SecurityCategory.FileHandling]: fileHandlingRules,
  [SecurityCategory.SecretsCredentials]: secretsRules,
  [SecurityCategory.FrontendSecurity]: frontendRules,
  [SecurityCategory.BusinessLogicPayment]: businessLogicRules,
  [SecurityCategory.LoggingMonitoring]: loggingRules,
};

export function getAllRules(): SecurityRule[] {
  return Object.values(allRulesByCategory).flat();
}

export function getRulesByCategory(category: SecurityCategory): SecurityRule[] {
  return allRulesByCategory[category] || [];
}

export function getRuleByCode(code: string): SecurityRule | undefined {
  return getAllRules().find(r => r.code === code);
}

export function getCategories(): SecurityCategory[] {
  return Object.values(SecurityCategory);
}
