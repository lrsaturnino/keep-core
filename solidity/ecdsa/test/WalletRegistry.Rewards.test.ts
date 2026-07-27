import { ethers, helpers } from "hardhat"
import { expect } from "chai"

import { params, walletRegistryFixture } from "./fixtures"
import ecdsaData from "./data/ecdsa"
import { hashDKGMembers, signAndSubmitCorrectDkgResult } from "./utils/dkg"
import { submitRelayEntry } from "./utils/randomBeacon"
import { createNewWallet } from "./utils/wallets"
import { signOperatorInactivityClaim } from "./utils/inactivity"

import type { ContractTransaction } from "ethers"
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"
import type { FakeContract } from "@defi-wonderland/smock"
import type { DkgResult } from "./utils/dkg"
import type { Operator, OperatorID } from "./utils/operators"
import type {
  SortitionPool,
  WalletRegistry,
  WalletRegistryGovernance,
  TokenStaking,
  IWalletOwner,
  T,
  IRandomBeacon,
  Allowlist,
} from "../typechain"

const { to1e18 } = helpers.number
const { mineBlocks } = helpers.time

const { createSnapshot, restoreSnapshot } = helpers.snapshot

async function rewardsBeneficiaryAddress(
  walletRegistry: WalletRegistry,
  staking: TokenStaking,
  stakingProvider: string
): Promise<string> {
  const allowlistAddr = await walletRegistry.allowlist()
  if (allowlistAddr !== ethers.constants.AddressZero) {
    const al = (await ethers.getContractAt(
      "Allowlist",
      allowlistAddr
    )) as Allowlist
    const r = await al.rolesOf(stakingProvider)
    return r.beneficiary
  }
  const r = await staking.rolesOf(stakingProvider)
  return r.beneficiary
}

describe("WalletRegistry - Rewards", () => {
  let tToken: T
  let walletRegistry: WalletRegistry
  let staking: TokenStaking
  let walletRegistryGovernance: WalletRegistryGovernance
  let sortitionPool: SortitionPool
  let randomBeacon: FakeContract<IRandomBeacon>
  let walletOwner: FakeContract<IWalletOwner>

  let deployer: SignerWithAddress
  let governance: SignerWithAddress
  let thirdParty: SignerWithAddress

  let members: Operator[]
  let membersIDs: OperatorID[]
  let walletID: string

  const walletPublicKey: string = ecdsaData.group1.publicKey

  const rewardAmount = to1e18(100000)

  before("load test fixture", async () => {
    // eslint-disable-next-line @typescript-eslint/no-extra-semi
    ;({
      tToken,
      walletRegistry,
      walletRegistryGovernance,
      staking,
      sortitionPool,
      randomBeacon,
      walletOwner,
      deployer,
      governance,
      thirdParty,
    } = await walletRegistryFixture({ useAllowlist: true }))
    ;({ members, walletID } = await createNewWallet(
      walletRegistry,
      walletOwner.wallet,
      randomBeacon,
      walletPublicKey
    ))

    membersIDs = members.map((member) => member.id)
  })

  describe("withdrawRewards", () => {
    context("when called for an unknown operator", () => {
      it("should revert", async () => {
        await expect(
          walletRegistry.withdrawRewards(thirdParty.address)
        ).to.be.revertedWithCustomError(walletRegistry, "UnknownOperator")
      })
    })

    context("when called for a known operator", () => {
      let stakingProvider: string
      let operator: string
      let beneficiary: string

      before(async () => {
        await createSnapshot()

        operator = members[0].signer.address
        stakingProvider = await walletRegistry.operatorToStakingProvider(
          operator
        )
        beneficiary = await rewardsBeneficiaryAddress(
          walletRegistry,
          staking,
          stakingProvider
        )

        // Allocate sortition pool rewards
        await tToken.connect(deployer).mint(deployer.address, rewardAmount)
        await tToken
          .connect(deployer)
          .approveAndCall(sortitionPool.address, rewardAmount, [])
      })

      after(async () => {
        await restoreSnapshot()
      })

      it("should withdraw rewards", async () => {
        expect(await tToken.balanceOf(beneficiary)).to.equal(0)
        await walletRegistry.withdrawRewards(stakingProvider)
        expect(await tToken.balanceOf(beneficiary)).to.be.gt(0)
      })

      it("should emit RewardsWithdrawn event", async () => {
        const balanceBefore = await tToken.balanceOf(beneficiary)
        const tx = await walletRegistry.withdrawRewards(stakingProvider)
        const balanceAfter = await tToken.balanceOf(beneficiary)
        const received = balanceAfter.sub(balanceBefore)

        await expect(tx)
          .to.emit(walletRegistry, "RewardsWithdrawn")
          .withArgs(stakingProvider, received)
      })
    })
  })

  describe("availableRewards", () => {
    context("when called for an unknown operator", () => {
      it("should revert", async () => {
        await expect(
          walletRegistry.availableRewards(thirdParty.address)
        ).to.be.revertedWithCustomError(walletRegistry, "UnknownOperator")
      })
    })

    context("when called for a known operator", () => {
      let stakingProvider: string
      let operator: string
      let beneficiary: string

      before(async () => {
        await createSnapshot()

        operator = members[0].signer.address
        stakingProvider = await walletRegistry.operatorToStakingProvider(
          operator
        )
        beneficiary = await rewardsBeneficiaryAddress(
          walletRegistry,
          staking,
          stakingProvider
        )

        // Allocate sortition pool rewards
        await tToken.connect(deployer).mint(deployer.address, rewardAmount)
        await tToken
          .connect(deployer)
          .approveAndCall(sortitionPool.address, rewardAmount, [])
      })

      after(async () => {
        await restoreSnapshot()
      })

      it("should return the amount of available rewards", async () => {
        let availableAmount = await walletRegistry.availableRewards(
          stakingProvider
        )

        const balanceBefore = await tToken.balanceOf(beneficiary)
        await walletRegistry.withdrawRewards(stakingProvider)
        const balanceAfter = await tToken.balanceOf(beneficiary)

        expect(availableAmount).to.equal(balanceAfter.sub(balanceBefore))

        availableAmount = await walletRegistry.availableRewards(stakingProvider)
        expect(availableAmount).to.equal(0)
      })
    })
  })

  describe("withdrawIneligibleRewards", () => {
    const inactiveMembersIndices = [1, 5, 10]
    const heartbeatFailed = false
    const groupThreshold = 51

    context("when called not by the governance", () => {
      it("should revert", async () => {
        await expect(
          walletRegistry
            .connect(thirdParty)
            .withdrawIneligibleRewards(thirdParty.address)
        ).to.be.revertedWith("Caller is not the governance")
      })
    })

    context("when called by the governance", () => {
      before(async () => {
        await createSnapshot()

        // Assume claim sender is the first signing member.
        const claimSender = members[0].signer

        const { signatures, signingMembersIndices } =
          await signOperatorInactivityClaim(
            members,
            0,
            walletPublicKey,
            heartbeatFailed,
            inactiveMembersIndices,
            groupThreshold
          )

        await walletRegistry.connect(claimSender).notifyOperatorInactivity(
          {
            walletID,
            inactiveMembersIndices,
            heartbeatFailed,
            signatures,
            signingMembersIndices,
          },
          0,
          membersIDs
        )

        // Allocate sortition pool rewards
        await tToken.connect(deployer).mint(deployer.address, rewardAmount)
        await tToken
          .connect(deployer)
          .approveAndCall(sortitionPool.address, rewardAmount, [])
      })

      after(async () => {
        await restoreSnapshot()
      })

      it("should withdraw ineligible rewards", async () => {
        // Withdraw rewards for ineligible operator. This action recalculates
        // the balance of "ineligible rewards" available for withdrawal from
        // the Sortition Pool
        const operator = members[0].signer.address
        const stakingProvider = await walletRegistry.operatorToStakingProvider(
          operator
        )
        await walletRegistry.withdrawRewards(stakingProvider)

        expect(await tToken.balanceOf(thirdParty.address)).to.equal(0)
        await walletRegistryGovernance
          .connect(governance)
          .withdrawIneligibleRewards(thirdParty.address)
        expect(await tToken.balanceOf(thirdParty.address)).to.be.gt(0)
      })
    })
  })

  describe("DKG misbehavior at the group quorum boundary", () => {
    // Ten misbehaved seats in a hundred-member group leave exactly ninety
    // active members — the largest exclusion the DKG validator accepts. Such
    // a result must be accepted on chain, and approval must make each of the
    // ten excluded operators ineligible for sortition pool rewards for the
    // governed ban duration.
    const misbehavedIndices = [1, 12, 23, 34, 45, 56, 67, 78, 89, 100]
    const boundaryWalletPublicKey: string = ecdsaData.group2.publicKey

    let boundaryDkgResult: DkgResult
    let boundarySubmitter: SignerWithAddress
    let misbehavedOperators: Operator[]
    let activeOperators: Operator[]

    before(async () => {
      await createSnapshot()

      await walletRegistry.connect(walletOwner.wallet).requestNewWallet()

      const { startBlock, dkgSeed } = await submitRelayEntry(
        walletRegistry,
        randomBeacon
      )

      let signers: Operator[]
        // eslint-disable-next-line @typescript-eslint/no-extra-semi
      ;({
        dkgResult: boundaryDkgResult,
        submitter: boundarySubmitter,
        signers,
      } = await signAndSubmitCorrectDkgResult(
        walletRegistry,
        boundaryWalletPublicKey,
        dkgSeed,
        startBlock,
        misbehavedIndices
      ))

      // The group is sampled with replacement, so one operator can hold
      // several seats: the ban is per operator, not per seat. The banned
      // set is every operator holding a misbehaved seat; operators remain
      // eligible only when none of their seats misbehaved.
      const bannedOperatorIds = new Set(
        misbehavedIndices.map((memberIndex) => signers[memberIndex - 1].id)
      )

      const seenBannedIds = new Set<number>()
      misbehavedOperators = misbehavedIndices
        .map((memberIndex) => signers[memberIndex - 1])
        .filter((operator) => {
          if (seenBannedIds.has(operator.id)) {
            return false
          }
          seenBannedIds.add(operator.id)
          return true
        })

      const seenActiveIds = new Set<number>()
      activeOperators = signers.filter((operator) => {
        if (bannedOperatorIds.has(operator.id)) {
          return false
        }
        if (seenActiveIds.has(operator.id)) {
          return false
        }
        seenActiveIds.add(operator.id)
        return true
      })

      expect(misbehavedOperators.length).to.be.gt(0)
      expect(activeOperators.length).to.be.gt(0)
    })

    after(async () => {
      await restoreSnapshot()
    })

    it("should withstand a challenge of the boundary result", async () => {
      await expect(
        walletRegistry.connect(thirdParty).challengeDkgResult(boundaryDkgResult)
      ).to.be.revertedWith("unjustified challenge")
    })

    context("when the boundary result is approved", () => {
      let approvalTx: ContractTransaction
      let banEndTimestamp: number

      before(async () => {
        await mineBlocks(params.dkgResultChallengePeriodLength)

        approvalTx = await walletRegistry
          .connect(boundarySubmitter)
          .approveDkgResult(boundaryDkgResult)

        banEndTimestamp =
          (await helpers.time.lastBlockTime()) +
          params.sortitionPoolRewardsBanDuration
      })

      it("should register the wallet with the ninety active members", async () => {
        const boundaryWalletID = ethers.utils.keccak256(boundaryWalletPublicKey)

        expect(
          (await walletRegistry.getWallet(boundaryWalletID)).membersIdsHash
        ).to.be.equal(
          hashDKGMembers(
            boundaryDkgResult.members as number[],
            misbehavedIndices
          )
        )
      })

      it("should ban all ten misbehaved operators from sortition pool rewards", async () => {
        const misbehavedIds = misbehavedIndices.map(
          (memberIndex) => boundaryDkgResult.members[memberIndex - 1]
        )

        await expect(approvalTx)
          .to.emit(sortitionPool, "IneligibleForRewards")
          .withArgs(misbehavedIds, banEndTimestamp)

        const eligibility = await Promise.all(
          misbehavedOperators.map((operator) =>
            sortitionPool.isEligibleForRewards(operator.signer.address)
          )
        )
        expect(eligibility).to.deep.equal(
          new Array(misbehavedOperators.length).fill(false)
        )

        const restorableAt = await Promise.all(
          misbehavedOperators.map(async (operator) =>
            (
              await sortitionPool.rewardsEligibilityRestorableAt(
                operator.signer.address
              )
            ).toNumber()
          )
        )
        expect(restorableAt).to.deep.equal(
          new Array(misbehavedOperators.length).fill(banEndTimestamp)
        )
      })

      it("should keep operators without a misbehaved seat eligible for rewards", async () => {
        const eligibility = await Promise.all(
          activeOperators.map((operator) =>
            sortitionPool.isEligibleForRewards(operator.signer.address)
          )
        )
        expect(eligibility).to.deep.equal(
          new Array(activeOperators.length).fill(true)
        )
      })

      it("should divert new reward allocations away from the banned operators", async () => {
        // Allocate sortition pool rewards after the ban.
        await tToken.connect(deployer).mint(deployer.address, rewardAmount)
        await tToken
          .connect(deployer)
          .approveAndCall(sortitionPool.address, rewardAmount, [])

        const bannedRewards = await Promise.all(
          misbehavedOperators.map(async (operator) =>
            walletRegistry.availableRewards(
              await walletRegistry.operatorToStakingProvider(
                operator.signer.address
              )
            )
          )
        )
        bannedRewards.forEach((amount, position) => {
          expect(
            amount,
            `rewards of banned operator [${position}]`
          ).to.be.equal(0)
        })

        const activeStakingProvider =
          await walletRegistry.operatorToStakingProvider(
            activeOperators[0].signer.address
          )
        expect(
          await walletRegistry.availableRewards(activeStakingProvider)
        ).to.be.gt(0)

        // Withdrawing for a banned operator recalculates the pool's
        // ineligible-rewards balance; the diverted share is then
        // withdrawable by the governance only.
        const bannedStakingProvider =
          await walletRegistry.operatorToStakingProvider(
            misbehavedOperators[0].signer.address
          )
        await walletRegistry.withdrawRewards(bannedStakingProvider)

        expect(await tToken.balanceOf(thirdParty.address)).to.equal(0)
        await walletRegistryGovernance
          .connect(governance)
          .withdrawIneligibleRewards(thirdParty.address)
        expect(await tToken.balanceOf(thirdParty.address)).to.be.gt(0)
      })
    })
  })
})
