/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    // Mock the vscode module since it's only available in the extension host
    '^vscode$': '<rootDir>/src/__tests__/__mocks__/vscode.ts',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
    }],
  },
  // Coverage ratchet: thresholds sit a few points below the measured
  // baseline (10.9.0: ~64% statements / 56% branches on touched files).
  // Raise them as coverage grows — never lower them to make a build pass.
  coverageThreshold: {
    global: {
      statements: 60,
      branches: 52,
      functions: 58,
      lines: 60,
    },
  },
};
