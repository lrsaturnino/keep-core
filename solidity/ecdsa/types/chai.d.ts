/**
 * Hardhat / waffle custom matchers used in tests (revertedWithCustomError).
 * Lives under types/ so Mocha does not try to execute this file as a test.
 */
declare namespace Chai {
  interface Assertion {
    revertedWithCustomError(contract: unknown, errorName: string): Promise<void>
  }
}
