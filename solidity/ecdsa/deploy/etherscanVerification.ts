import type { HardhatRuntimeEnvironment } from "hardhat/types"

/**
 * Runs Etherscan verification without failing the deploy when the explorer API
 * errors (rate limits, bytecode mismatch, missing keys). Use for all deploy
 * scripts so behavior matches across the stack.
 */
export default async function verifyOnEtherscanOrContinue(
  hre: HardhatRuntimeEnvironment,
  verify: () => Promise<unknown>
): Promise<void> {
  try {
    await verify()
  } catch (err) {
    hre.deployments.log(
      `Etherscan verification skipped (deploy continues): ${err}`
    )
  }
}
