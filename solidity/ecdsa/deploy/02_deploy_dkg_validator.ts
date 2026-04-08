import type { HardhatRuntimeEnvironment } from "hardhat/types"
import type { DeployFunction } from "hardhat-deploy/types"

const func: DeployFunction = async (hre: HardhatRuntimeEnvironment) => {
  const { getNamedAccounts, deployments, helpers } = hre
  const { deployer } = await getNamedAccounts()

  // full-redeploy-sepolia-stack.sh sets this when --dkg-group-size 3: incremental compile
  // can still leave groupSize=100 bytecode in artifacts without a forced compile.
  if (process.env.THRESHOLD_FORCE_DKG_COMPILE === "1") {
    await hre.run("compile", { force: true })
  }

  const EcdsaSortitionPool = await deployments.get("EcdsaSortitionPool")

  // skipIfAlreadyDeployed: false — so hardhat-deploy compares on-chain bytecode to the
  // current artifact. With true, an existing deployments/*.json skips deploy entirely
  // even when Solidity was patched (e.g. groupSize 100 → 3), leaving stale contracts.
  const EcdsaDkgValidator = await deployments.deploy("EcdsaDkgValidator", {
    from: deployer,
    args: [EcdsaSortitionPool.address],
    log: true,
    waitConfirmations: 1,
    skipIfAlreadyDeployed: false,
  })

  if (hre.network.tags.etherscan) {
    await helpers.etherscan.verify(EcdsaDkgValidator)
  }

  if (hre.network.tags.tenderly) {
    await hre.tenderly.verify({
      name: "EcdsaDkgValidator",
      address: EcdsaDkgValidator.address,
    })
  }

  return true
}

export default func

func.tags = ["EcdsaDkgValidator"]
func.dependencies = ["EcdsaSortitionPool"]
func.id = "deploy_ecdsa_dkg_validator"
