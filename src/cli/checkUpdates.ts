#!/usr/bin/env node

import * as path from 'path';
import { checkDependencies, formatResultsAsText } from '../dependencyChecker';

async function main(): Promise<void> {
  const projectPath = process.argv[2] || process.cwd();
  const resolvedPath = path.resolve(projectPath);

  console.log('Caspian Security: Dependency & Stack Update Check');
  console.log(`Project: ${resolvedPath}`);
  console.log('='.repeat(50));
  console.log('');

  try {
    const result = await checkDependencies(resolvedPath);
    const output = formatResultsAsText(result);
    console.log(output);

    // Exit with code 1 if there are critical/high vulnerabilities
    const hasHighSeverity = result.auditSummary.vulnerabilities.some(
      v => v.severity === 'high' || v.severity === 'critical'
    );
    process.exit(hasHighSeverity ? 1 : 0);
  } catch (error) {
    console.error('Error running dependency check:', error);
    process.exit(2);
  }
}

main();
