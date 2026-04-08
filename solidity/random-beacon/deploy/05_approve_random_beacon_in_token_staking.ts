import type { HardhatRuntimeEnvironment } from "hardhat/types"
import type { DeployFunction } from "hardhat-deploy/types"

// ApplicationStatus enum: NOT_APPROVED=0, APPROVED=1, PAUSED=2, DISABLED=3
const APPLICATION_STATUS_APPROVED = 1

const func: DeployFunction = async (hre: HardhatRuntimeEnvironment) => {
  const { getNamedAccounts, deployments, ethers } = hre
  const { deployer } = await getNamedAccounts()
  const { execute, get } = deployments

  const RandomBeacon = await deployments.get("RandomBeacon")
  const TokenStaking = await get("TokenStaking")

  const hasApproveApplication = TokenStaking.abi.some(
    (item) =>
      item.type === "function" && item.name === "approveApplication"
  )

  if (!hasApproveApplication) {
    hre.deployments.log(
      "TokenStaking does not have approveApplication (Threshold TokenStaking); skipping"
    )
    return
  }

  // Skip if RandomBeacon is already approved (idempotent for re-runs)
  const tokenStakingContract = await ethers.getContractAt(
    "TokenStaking",
    TokenStaking.address
  )
  const appInfo = await tokenStakingContract.applicationInfo(
    RandomBeacon.address
  )
  if (appInfo.status === APPLICATION_STATUS_APPROVED) {
    hre.deployments.log(
      "RandomBeacon already approved in TokenStaking; skipping"
    )
    return
  }

  await execute(
    "TokenStaking",
    { from: deployer, log: true, waitConfirmations: 1 },
    "approveApplication",
    RandomBeacon.address
  )
}

export default func

func.tags = ["RandomBeaconApprove"]
func.dependencies = ["TokenStaking", "RandomBeacon"]

// Skip for mainnet (already approved).
func.skip = async (hre: HardhatRuntimeEnvironment): Promise<boolean> =>
  hre.network.name === "mainnet"
