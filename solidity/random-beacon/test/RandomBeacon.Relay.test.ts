/* eslint-disable @typescript-eslint/no-unused-expressions, no-await-in-loop, @typescript-eslint/no-extra-semi */

import { ethers, waffle, helpers } from "hardhat"
import { expect } from "chai"
import { BigNumber } from "ethers"

import blsData from "./data/bls"
import {
  constants,
  dkgState,
  params,
  randomBeaconDeployment,
  blsDeployment,
} from "./fixtures"
import { createGroup, hashUint32Array } from "./utils/groups"
import { signOperatorInactivityClaim } from "./utils/inactivity"
import { registerOperators } from "./utils/operators"
import { fakeTokenStaking } from "./mocks/staking"

import type { Groups } from "../typechain/RandomBeacon"
import type { Operator, OperatorID } from "./utils/operators"
import type { FakeContract } from "@defi-wonderland/smock"
import type {
  RandomBeacon,
  RandomBeaconStub,
  T,
  RelayStub,
  SortitionPool,
  TokenStaking,
  BLS,
  RandomBeaconGovernance,
  ReimbursementPool,
} from "../typechain"
import type { Address } from "hardhat-deploy/types"
import type { ContractTransaction, BigNumberish } from "ethers"
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"

const { mineBlocks, mineBlocksTo } = helpers.time
const { to1e18 } = helpers.number
const ZERO_ADDRESS = ethers.constants.AddressZero
const { createSnapshot, restoreSnapshot } = helpers.snapshot
const { provider } = waffle

// FIXME: As a workaround for a bug https://github.com/dethcrypto/TypeChain/issues/601
// we declare a new type instead of using `RandomBeaconStub & RandomBeacon` intersection.
type RandomBeaconTest = RandomBeacon & {
  dkgLockState: () => Promise<ContractTransaction>
  // Test-only setter exposed by RandomBeaconStub, used by the reimbursement
  // negative control to run the pre-fix gas offset.
  setRelayEntrySubmissionGasOffset: (
    offset: BigNumberish
  ) => Promise<ContractTransaction>
}

async function fixture() {
  const deployment = await randomBeaconDeployment()

  // Additional contracts needed by this test suite.
  const relayStub = (await (
    await ethers.getContractFactory("RelayStub")
  ).deploy()) as RelayStub
  const bls = (await blsDeployment()).bls as BLS

  // Register operators in the sortition pool to make group creation
  // possible.
  // Accounts offset provided to slice getUnnamedSigners have to include number
  // of unnamed accounts that were already used.
  const operators = await registerOperators(
    deployment.randomBeacon as RandomBeacon,
    deployment.t as T,
    constants.groupSize,
    4
  )

  return {
    randomBeacon: deployment.randomBeacon as RandomBeaconTest,
    randomBeaconGovernance:
      deployment.randomBeaconGovernance as RandomBeaconGovernance,
    sortitionPool: deployment.sortitionPool as SortitionPool,
    staking: deployment.staking as TokenStaking,
    reimbursementPool: deployment.reimbursementPool as ReimbursementPool,
    relayStub,
    bls,
    operators,
  }
}

// RELAY_ENTRY_GAS_PRICE is an explicit legacy gas price set on every measured
// relay-entry submission. It is below ReimbursementPool.maxGasPrice (500 gwei),
// so the reimbursement uses tx.gasprice and receipt.effectiveGasPrice equals it.
// That makes all balance arithmetic below deterministic.
//
// Measurement environment (must stay in sync with hardhat.config.ts): solc
// 0.8.17 with the optimizer enabled at its default 200 runs and the default EVM
// version (london). The Hardhat network hardfork is pinned to "london" in
// hardhat.config.ts; Hardhat 2.10.0 would otherwise default to "arrowGlacier",
// which is gas-identical to london (it only delays the difficulty bomb), so the
// pin makes the network hardfork explicit and aligned with the solc EVM target
// without changing any measured gas. These settings define the measured gas;
// changing any of them can move the required offset and forces a re-measurement.
const RELAY_ENTRY_GAS_PRICE = ethers.utils.parseUnits("100", "gwei")

// RELAY_ENTRY_OFFSET_FIX is the current relay entry submission gas offset;
// RELAY_ENTRY_OFFSET_PRE_FIX is the value before commit edb51da0 raised it. The
// 2,200-gas difference is exactly the adjustment the reimbursement must track.
const RELAY_ENTRY_OFFSET_FIX = 13_450
const RELAY_ENTRY_OFFSET_PRE_FIX = 11_250
const RELAY_ENTRY_OFFSET_ADJUSTMENT = BigNumber.from(
  RELAY_ENTRY_OFFSET_FIX - RELAY_ENTRY_OFFSET_PRE_FIX
)

// TUNED_OVER_REIMBURSEMENT_GAS_TOLERANCE bounds how much more than its true cost
// the submitter may be refunded at the current offset for the overload the
// offset is tuned for: submitRelayEntry(bytes,uint32[]). The offset is set to
// just cover that overload (measured ~82 gas of headroom), so this bound is
// tight.
const TUNED_OVER_REIMBURSEMENT_GAS_TOLERANCE = BigNumber.from(5_000)

// BYTES_ONLY_OVER_REIMBURSEMENT_CEILING_GAS bounds the over-reimbursement of the
// lighter submitRelayEntry(bytes) overload. Both overloads share a single
// _relayEntrySubmissionGasOffset. That offset is tuned for the heavier
// bytes,uint32[] overload, whose uint32[64] membersIDs array is charged as
// intrinsic calldata gas BEFORE the in-function `gasStart = gasleft()` snapshot
// and so is never measured. The bytes-only overload carries none of that
// calldata, so the shared offset structurally over-reimburses it by exactly that
// fixed slack: measured +9,563 gas at the current offset (and +7,363 gas at the
// pre-fix offset, i.e. still fully reimbursed - the fix is not needed for this
// path). The lighter overload therefore CANNOT satisfy the 5,000-gas tuned
// tolerance nor under-reimburse at the pre-fix offset; that is a property of the
// single-offset contract design, not a gap in the test. This ceiling brackets
// the measured 9,563-gas slack with headroom so it cannot silently grow.
const BYTES_ONLY_OVER_REIMBURSEMENT_CEILING_GAS = BigNumber.from(10_000)

interface ReimbursementMeasurement {
  netWei: BigNumber
  gasPrice: BigNumber
  // Signed net reimbursement in gas units: positive = over-reimbursed,
  // negative = under-reimbursed.
  netGas: BigNumber
  refund: BigNumber
  transactionCost: BigNumber
}

// measureRelayEntryReimbursement records the submitter and reimbursement-pool
// balances around a relay-entry submission and derives the submitter's net
// reimbursement. It asserts the exact conservation identity - the submitter's
// balance change equals the pool refund it received minus the gas it paid - and
// returns the net in wei and in gas units.
async function measureRelayEntryReimbursement(
  reimbursementPool: ReimbursementPool,
  submitter: SignerWithAddress,
  submitterBefore: BigNumber,
  poolBefore: BigNumber,
  tx: ContractTransaction
): Promise<ReimbursementMeasurement> {
  const receipt = await tx.wait()

  const submitterAfter = await provider.getBalance(submitter.address)
  const poolAfter = await provider.getBalance(reimbursementPool.address)

  const transactionCost = receipt.gasUsed.mul(receipt.effectiveGasPrice)
  const refund = poolBefore.sub(poolAfter)
  const netWei = submitterAfter.sub(submitterBefore)

  // Conservation of ETH: the submitter sends no value and receives only the
  // pool refund, so its balance change must equal refund - gas paid. Exact.
  expect(netWei).to.equal(refund.sub(transactionCost))

  const gasPrice = receipt.effectiveGasPrice
  return {
    netWei,
    gasPrice,
    netGas: netWei.div(gasPrice),
    refund,
    transactionCost,
  }
}

describe("RandomBeacon - Relay", () => {
  let governance: SignerWithAddress
  let requester: SignerWithAddress
  let notifier: SignerWithAddress
  let submitter: SignerWithAddress
  let thirdParty: SignerWithAddress
  let members: Operator[]
  let membersIDs: OperatorID[]
  let membersAddresses: Address[]

  let randomBeacon: RandomBeaconTest
  let randomBeaconGovernance: RandomBeaconGovernance
  let sortitionPool: SortitionPool
  let staking: TokenStaking
  let reimbursementPool: ReimbursementPool
  let relayStub: RelayStub
  let bls: BLS

  before(async () => {
    ;({ governance } = await helpers.signers.getNamedSigners())
    ;[thirdParty, requester, notifier, submitter] =
      await helpers.signers.getUnnamedSigners()
    ;({
      randomBeacon,
      sortitionPool,
      staking,
      reimbursementPool,
      relayStub,
      bls,
      operators: members,
      randomBeaconGovernance,
    } = await waffle.loadFixture(fixture))

    membersIDs = members.map((member) => member.id)
    membersAddresses = members.map((member) => member.signer.address)

    await randomBeaconGovernance
      .connect(governance)
      .setRequesterAuthorization(requester.address, true)
  })

  // measureRelayEntrySubmissionAtOffset sets the relay entry submission gas
  // offset, runs `submit`, and returns the reimbursement measurement, all inside
  // a snapshot so both the offset change and the submission are reverted. The
  // caller must already have a relay request in progress.
  async function measureRelayEntrySubmissionAtOffset(
    offset: number,
    submit: () => Promise<ContractTransaction>
  ): Promise<ReimbursementMeasurement> {
    await createSnapshot()

    await randomBeacon.setRelayEntrySubmissionGasOffset(offset)

    const submitterBefore = await provider.getBalance(submitter.address)
    const poolBefore = await provider.getBalance(reimbursementPool.address)

    const tx = await submit()

    const measurement = await measureRelayEntryReimbursement(
      reimbursementPool,
      submitter,
      submitterBefore,
      poolBefore,
      tx
    )

    await restoreSnapshot()

    return measurement
  }

  describe("requestRelayEntry", () => {
    context("when requester is not authorized", () => {
      it("should revert", async () => {
        await expect(
          randomBeacon.connect(thirdParty).requestRelayEntry(ZERO_ADDRESS)
        ).to.be.revertedWith("Requester must be authorized")
      })
    })

    context("when requester is authorized", () => {
      context("when groups exist", () => {
        before(async () => {
          await createSnapshot()

          await createGroup(randomBeacon, members)
        })

        after(async () => {
          await restoreSnapshot()
        })

        context("when there is no other relay entry in progress", () => {
          let tx: ContractTransaction

          before(async () => {
            await createSnapshot()
          })

          after(async () => {
            await restoreSnapshot()
          })

          context(
            "when relay request does not hit group creation frequency threshold",
            () => {
              before(async () => {
                await createSnapshot()

                tx = await randomBeacon
                  .connect(requester)
                  .requestRelayEntry(ZERO_ADDRESS)
              })

              after(async () => {
                await restoreSnapshot()
              })

              it("should emit RelayEntryRequested event", async () => {
                await expect(tx)
                  .to.emit(randomBeacon, "RelayEntryRequested")
                  .withArgs(1, 0, blsData.previousEntry)
              })

              it("should not lock DKG state", async () => {
                expect(await randomBeacon.getGroupCreationState()).to.be.equal(
                  dkgState.IDLE
                )
                expect(await sortitionPool.isLocked()).to.be.false
              })
            }
          )

          context(
            "when relay request hits group creation frequency threshold",
            () => {
              before(async () => {
                await createSnapshot()

                // Force group creation on each relay entry.
                await randomBeaconGovernance
                  .connect(governance)
                  .beginGroupCreationFrequencyUpdate(1)
                await helpers.time.increaseTime(params.governanceDelay)
                await randomBeaconGovernance
                  .connect(governance)
                  .finalizeGroupCreationFrequencyUpdate()

                tx = await randomBeacon
                  .connect(requester)
                  .requestRelayEntry(ZERO_ADDRESS)
              })

              after(async () => {
                await restoreSnapshot()
              })

              it("should emit RelayEntryRequested event", async () => {
                await expect(tx)
                  .to.emit(randomBeacon, "RelayEntryRequested")
                  .withArgs(1, 0, blsData.previousEntry)
              })

              it("should lock DKG state", async () => {
                expect(await randomBeacon.getGroupCreationState()).to.be.equal(
                  dkgState.AWAITING_SEED
                )
                expect(await sortitionPool.isLocked()).to.be.true
              })

              it("should emit DkgStateLocked event", async () => {
                await expect(tx).to.emit(randomBeacon, "DkgStateLocked")
              })
            }
          )
        })

        context("when there is another relay entry in progress", () => {
          before(async () => {
            await createSnapshot()

            await randomBeacon
              .connect(requester)
              .requestRelayEntry(ZERO_ADDRESS)
          })

          after(async () => {
            await restoreSnapshot()
          })

          it("should revert", async () => {
            await expect(
              randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
            ).to.be.revertedWith("Another relay request in progress")
          })
        })
      })

      context("when no groups exist", () => {
        it("should revert", async () => {
          await expect(
            randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
          ).to.be.revertedWith("No active groups")
        })
      })
    })
  })

  describe("submitRelayEntry(bytes)", () => {
    before(async () => {
      await createSnapshot()

      await createGroup(randomBeacon, members)
    })

    after(async () => {
      await restoreSnapshot()
    })

    context("when relay request is in progress", () => {
      before(async () => {
        await createSnapshot()

        await randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
      })

      after(async () => {
        await restoreSnapshot()
      })

      context("when relay entry has not timed out", () => {
        context("when entry is valid", () => {
          context("when result is submitted before the soft timeout", () => {
            let tx: ContractTransaction
            let initialSubmitterBalance: BigNumber
            let initialReimbursementPoolBalance: BigNumber

            before(async () => {
              await createSnapshot()

              initialSubmitterBalance = await provider.getBalance(
                submitter.address
              )
              initialReimbursementPoolBalance = await provider.getBalance(
                reimbursementPool.address
              )

              tx = await randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes)"](blsData.groupSignature, {
                  gasPrice: RELAY_ENTRY_GAS_PRICE,
                })
            })

            after(async () => {
              await restoreSnapshot()
            })

            it("should not reward the notifier", async () => {
              await expect(tx).to.not.emit(staking, "NotifierRewarded")
            })

            it("should not slash any members", async () => {
              await expect(tx).to.not.emit(staking, "TokensSeized")
              expect(await staking.getSlashingQueueLength()).to.be.equal(0)
            })

            it("should emit RelayEntrySubmitted event", async () => {
              await expect(tx)
                .to.emit(randomBeacon, "RelayEntrySubmitted")
                .withArgs(1, submitter.address, blsData.groupSignature)
            })

            it("should terminate the relay request", async () => {
              expect(await randomBeacon.isRelayRequestInProgress()).to.be.false
            })

            it("should fully reimburse the submitter (no under-reimbursement)", async () => {
              const measurement = await measureRelayEntryReimbursement(
                reimbursementPool,
                submitter,
                initialSubmitterBalance,
                initialReimbursementPoolBalance,
                tx
              )

              // The submitter is at least made whole. The bytes-only overload
              // carries little calldata, so the offset - tuned for the
              // bytes,uint32[] overload - over-reimburses this one by a larger,
              // still-safe margin. Its exact offset sensitivity is pinned by the
              // negative-control context below.
              // The submitter is at least made whole: no under-reimbursement.
              expect(
                measurement.netWei,
                "submitter was under-reimbursed at the current offset"
              ).to.be.gte(0)

              // The single _relayEntrySubmissionGasOffset is tuned for the
              // heavier submitRelayEntry(bytes,uint32[]) overload, whose
              // uint32[64] membersIDs calldata is charged as intrinsic gas
              // before `gasStart = gasleft()` and is therefore never measured.
              // This lighter bytes-only overload carries none of that calldata,
              // so the same offset structurally over-reimburses it by that
              // fixed slack (measured 9,563 gas under the pinned environment).
              // Bound it so the over-reimbursement cannot silently grow, e.g.
              // if the offset is inflated further.
              expect(
                measurement.netGas,
                "bytes-only over-reimbursement exceeds the documented structural ceiling"
              ).to.be.lte(BYTES_ONLY_OVER_REIMBURSEMENT_CEILING_GAS)
            })
          })

          context(
            "when the relay entry submission gas offset changes (negative control)",
            () => {
              const submit = () =>
                randomBeacon
                  .connect(submitter)
                  ["submitRelayEntry(bytes)"](blsData.groupSignature, {
                    gasPrice: RELAY_ENTRY_GAS_PRICE,
                  })

              it("is already fully reimbursed at the pre-fix offset and tracks the 2,200-gas fix adjustment", async () => {
                const preFix = await measureRelayEntrySubmissionAtOffset(
                  RELAY_ENTRY_OFFSET_PRE_FIX,
                  submit
                )
                const current = await measureRelayEntrySubmissionAtOffset(
                  RELAY_ENTRY_OFFSET_FIX,
                  submit
                )

                // Fully reimbursed at the current offset.
                expect(
                  current.netWei,
                  "submitter was under-reimbursed at the current offset"
                ).to.be.gte(0)

                // Unlike the bytes,uint32[] overload - which under-reimburses at
                // the pre-fix offset and is exactly the reason edb51da0 raised
                // the offset - this lighter bytes-only overload is ALREADY fully
                // reimbursed at the pre-fix 11,250 offset (measured +7,363 gas).
                // The fix is therefore not required for this path and does not
                // harm it; this is the meaningful, non-tautological control that
                // pins the old offset as sufficient for bytes-only.
                expect(
                  preFix.netWei,
                  "pre-fix offset should already fully reimburse the bytes-only overload"
                ).to.be.gte(0)

                // The current offset refunds exactly the 2,200-gas fix
                // adjustment more than the pre-fix offset, confirming the
                // reimbursement tracks the offset for this overload too.
                expect(
                  current.netGas.sub(preFix.netGas),
                  "reimbursement did not track the 2,200-gas offset change"
                ).to.equal(RELAY_ENTRY_OFFSET_ADJUSTMENT)
              })
            }
          )

          context("when result is submitted after the soft timeout", () => {
            before(async () => {
              await createSnapshot()
            })

            after(async () => {
              await restoreSnapshot()
            })

            it("should revert", async () => {
              await mineBlocks(params.relayEntrySoftTimeout + 1)
              await expect(
                randomBeacon
                  .connect(submitter)
                  ["submitRelayEntry(bytes)"](blsData.groupSignature)
              ).to.be.revertedWith("Relay entry soft timeout passed")
            })
          })

          context("when DKG is awaiting a seed", () => {
            let tx: ContractTransaction

            before(async () => {
              await createSnapshot()

              // Simulate DKG is awaiting a seed.
              await randomBeacon.dkgLockState()

              tx = await randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes)"](blsData.groupSignature)
            })

            after(async () => {
              await restoreSnapshot()
            })

            it("should emit DkgStarted event", async () => {
              await expect(tx)
                .to.emit(randomBeacon, "DkgStarted")
                .withArgs(blsData.groupSignatureUint256)
            })
          })
        })

        context("when entry is invalid", () => {
          it("should revert", async () => {
            await expect(
              randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes)"](blsData.nextGroupSignature)
            ).to.be.revertedWith("Invalid entry")
          })
        })
      })
    })
  })

  describe("submitRelayEntry(bytes,uint32[])", () => {
    before(async () => {
      await createSnapshot()

      await createGroup(randomBeacon, members)
    })

    after(async () => {
      await restoreSnapshot()
    })

    context("when relay request is in progress", () => {
      before(async () => {
        await createSnapshot()

        await randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
      })

      after(async () => {
        await restoreSnapshot()
      })

      context("when the input params are valid", () => {
        context("when result is submitted before the soft timeout", () => {
          let tx: ContractTransaction
          let initialSubmitterBalance: BigNumber
          let initialReimbursementPoolBalance: BigNumber

          before(async () => {
            await createSnapshot()

            initialSubmitterBalance = await provider.getBalance(
              submitter.address
            )
            initialReimbursementPoolBalance = await provider.getBalance(
              reimbursementPool.address
            )

            tx = await randomBeacon
              .connect(submitter)
              ["submitRelayEntry(bytes,uint32[])"](
                blsData.groupSignature,
                membersIDs,
                { gasPrice: RELAY_ENTRY_GAS_PRICE }
              )
          })

          after(async () => {
            await restoreSnapshot()
          })

          it("should not reward the notifier", async () => {
            await expect(tx).to.not.emit(staking, "NotifierRewarded")
          })

          it("should not slash any members", async () => {
            await expect(tx).to.not.emit(staking, "TokensSeized")
            expect(await staking.getSlashingQueueLength()).to.be.equal(0)

            await expect(tx).to.not.emit(randomBeacon, "RelayEntryDelaySlashed")
          })

          it("should emit RelayEntrySubmitted event", async () => {
            await expect(tx)
              .to.emit(randomBeacon, "RelayEntrySubmitted")
              .withArgs(1, submitter.address, blsData.groupSignature)
          })

          it("should terminate the relay request", async () => {
            expect(await randomBeacon.isRelayRequestInProgress()).to.be.false
          })

          it("should fully reimburse the submitter within the tuned over-reimbursement tolerance", async () => {
            const measurement = await measureRelayEntryReimbursement(
              reimbursementPool,
              submitter,
              initialSubmitterBalance,
              initialReimbursementPoolBalance,
              tx
            )

            // The offset is tuned for this overload, so the submitter is made
            // whole with only a small over-reimbursement margin.
            expect(
              measurement.netWei,
              "submitter was under-reimbursed at the current offset"
            ).to.be.gte(0)
            expect(
              measurement.netGas,
              "over-reimbursement exceeds the tuned tolerance"
            ).to.be.lte(TUNED_OVER_REIMBURSEMENT_GAS_TOLERANCE)
          })
        })

        context(
          "when the relay entry submission gas offset changes (negative control)",
          () => {
            const submit = () =>
              randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes,uint32[])"](
                  blsData.groupSignature,
                  membersIDs,
                  { gasPrice: RELAY_ENTRY_GAS_PRICE }
                )

            it("under-reimburses at the pre-fix offset and reimburses exactly the 2,200-gas fix adjustment more at the current offset", async () => {
              const preFix = await measureRelayEntrySubmissionAtOffset(
                RELAY_ENTRY_OFFSET_PRE_FIX,
                submit
              )
              const current = await measureRelayEntrySubmissionAtOffset(
                RELAY_ENTRY_OFFSET_FIX,
                submit
              )

              // Fully reimbursed at the current offset...
              expect(
                current.netWei,
                "submitter was under-reimbursed at the current offset"
              ).to.be.gte(0)

              // ...but under-reimbursed at the pre-fix offset. This overload is
              // the one the offset is tuned for, so the fix is exactly what
              // makes the submitter whole.
              expect(
                preFix.netWei,
                "pre-fix offset did not under-reimburse the submitter"
              ).to.be.lt(0)

              // The difference is exactly the 2,200-gas fix adjustment.
              expect(
                current.netGas.sub(preFix.netGas),
                "reimbursement did not track the 2,200-gas offset change"
              ).to.equal(RELAY_ENTRY_OFFSET_ADJUSTMENT)
            })
          }
        )

        context("when result is submitted after the soft timeout", () => {
          let initialSubmitterBalance: BigNumber
          let initialReimbursementPoolBalance: BigNumber
          // `relayEntrySubmissionFailureSlashingAmount = 1000e18`.
          // 75% of the soft timeout period elapsed so we expect
          // `750e18` to be slashed.
          const slashingAmount = to1e18(750)

          let submissionTx: ContractTransaction
          let slashingTx: ContractTransaction

          before(async () => {
            await createSnapshot()

            // Let's assume we want to submit the relay entry after 75%
            // of the soft timeout period elapses. If so we need to
            // mine the following number of blocks:
            // `relayEntrySoftTimeout +
            // (0.75 * relayEntryHardTimeout)`. However, we need to
            // subtract one block because the relay entry submission
            // transaction will move the blockchain ahead by one block
            // due to the Hardhat auto-mine feature.
            await mineBlocks(
              params.relayEntrySoftTimeout +
                0.75 * params.relayEntryHardTimeout -
                1
            )

            initialSubmitterBalance = await provider.getBalance(
              submitter.address
            )
            initialReimbursementPoolBalance = await provider.getBalance(
              reimbursementPool.address
            )
            submissionTx = await randomBeacon
              .connect(submitter)
              ["submitRelayEntry(bytes,uint32[])"](
                blsData.groupSignature,
                membersIDs,
                { gasPrice: RELAY_ENTRY_GAS_PRICE }
              )

            slashingTx = await staking.processSlashing(membersAddresses.length)
          })

          after(async () => {
            await restoreSnapshot()
          })

          // TokenStaking.slash function is called that doesn't reward the notifier.
          it("should not reward the notifier", async () => {
            await expect(submissionTx).to.not.emit(staking, "NotifierRewarded")
          })

          it("should slash a correct portion of the slashing amount for all group members", async () => {
            for (let i = 0; i < membersAddresses.length; i++) {
              const stakingProvider =
                await randomBeacon.operatorToStakingProvider(
                  membersAddresses[i]
                )

              await expect(slashingTx)
                .to.emit(staking, "TokensSeized")
                .withArgs(stakingProvider, slashingAmount, false)
            }
          })

          it("should emit RelayEntryDelaySlashed event", async () => {
            await expect(submissionTx)
              .to.emit(randomBeacon, "RelayEntryDelaySlashed")
              .withArgs(1, slashingAmount, membersAddresses)
          })

          it("should emit RelayEntrySubmitted event", async () => {
            await expect(submissionTx)
              .to.emit(randomBeacon, "RelayEntrySubmitted")
              .withArgs(1, submitter.address, blsData.groupSignature)
          })

          it("should terminate the relay request", async () => {
            expect(await randomBeacon.isRelayRequestInProgress()).to.be.false
          })

          it("should fully reimburse the submitter within the tuned over-reimbursement tolerance", async () => {
            // The slashingTx that ran after submissionTx in the before hook is a
            // separate staking.processSlashing call sent by another signer; it
            // seizes staked T tokens and touches neither the submitter's ETH
            // balance nor the reimbursement pool, so the measured net below is
            // exactly submissionTx's reimbursement.
            const measurement = await measureRelayEntryReimbursement(
              reimbursementPool,
              submitter,
              initialSubmitterBalance,
              initialReimbursementPoolBalance,
              submissionTx
            )

            // Same offset economics as the before-soft-timeout path: the delay
            // slashing is only queued inside the measured gasStart..gasleft()
            // window (the actual seizure happens in the separate slashingTx), and
            // the unmeasured intrinsic-calldata slack is identical because the
            // arguments are the same bytes + uint32[] pair. The submitter is made
            // whole with only the tuned over-reimbursement margin.
            expect(
              measurement.netWei,
              "submitter was under-reimbursed at the current offset"
            ).to.be.gte(0)
            expect(
              measurement.netGas,
              "over-reimbursement exceeds the tuned tolerance"
            ).to.be.lte(TUNED_OVER_REIMBURSEMENT_GAS_TOLERANCE)
          })
        })
      })

      context("when the input params are invalid", () => {
        before(async () => {
          await createSnapshot()
          await mineBlocks(params.relayEntrySoftTimeout + 1)
        })

        after(async () => {
          await restoreSnapshot()
        })

        context("when entry is not valid", () => {
          it("should revert", async () => {
            await expect(
              randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes,uint32[])"](
                  blsData.nextGroupSignature,
                  membersIDs
                )
            ).to.be.revertedWith("Invalid entry")
          })
        })

        context("when group members are invalid", () => {
          it("should revert", async () => {
            const invalidMembersId = [0, 1, 42]
            await expect(
              randomBeacon
                .connect(submitter)
                ["submitRelayEntry(bytes,uint32[])"](
                  blsData.nextGroupSignature,
                  invalidMembersId
                )
            ).to.be.revertedWith("Invalid group members")
          })
        })
      })

      context("when a relay entry has timed out", () => {
        it("should revert", async () => {
          await mineBlocks(
            params.relayEntrySoftTimeout + params.relayEntryHardTimeout
          )

          await expect(
            randomBeacon
              .connect(submitter)
              ["submitRelayEntry(bytes,uint32[])"](
                blsData.nextGroupSignature,
                membersIDs
              )
          ).to.be.revertedWith("Relay request timed out")
        })
      })
    })
  })

  describe("reportRelayEntryTimeout", () => {
    before(async () => {
      await createSnapshot()

      await createGroup(randomBeacon, members)
      await randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
    })

    after(async () => {
      await restoreSnapshot()
    })

    context("when relay entry timed out", () => {
      before(async () => {
        await createSnapshot()

        await mineBlocks(
          params.relayEntrySoftTimeout + params.relayEntryHardTimeout
        )
      })

      after(async () => {
        await restoreSnapshot()
      })

      context(
        "when other active groups exist after timeout is reported",
        () => {
          let reportTx: ContractTransaction
          let slashingTx: ContractTransaction

          before(async () => {
            await createSnapshot()

            await (randomBeacon as unknown as RandomBeaconStub).roughlyAddGroup(
              "0x01",
              hashUint32Array(membersIDs)
            )

            reportTx = await randomBeacon
              .connect(notifier)
              .reportRelayEntryTimeout(membersIDs)

            slashingTx = await staking.processSlashing(membersAddresses.length)
          })

          after(async () => {
            await restoreSnapshot()
          })

          it("should reward the notifier", async () => {
            await expect(reportTx)
              .to.emit(staking, "NotifierRewarded")
              .withArgs(
                notifier.address,
                constants.tokenStakingNotificationReward
                  .mul(params.relayEntryTimeoutNotificationRewardMultiplier)
                  .div(100)
                  .mul(membersIDs.length)
              )
          })

          it("should slash the full slashing amount for all group members", async () => {
            for (let i = 0; i < membersAddresses.length; i++) {
              const stakingProvider =
                await randomBeacon.operatorToStakingProvider(
                  membersAddresses[i]
                )

              await expect(slashingTx)
                .to.emit(staking, "TokensSeized")
                .withArgs(
                  stakingProvider,
                  params.relayEntrySubmissionFailureSlashingAmount,
                  false
                )
            }
          })

          it("should emit RelayEntryTimeoutSlashed event", async () => {
            await expect(reportTx)
              .to.emit(randomBeacon, "RelayEntryTimeoutSlashed")
              .withArgs(
                1,
                params.relayEntrySubmissionFailureSlashingAmount,
                membersAddresses
              )
          })

          it("should not emit RelayEntryTimeoutSlashingFailed event", async () => {
            await expect(reportTx).to.not.emit(
              randomBeacon,
              "RelayEntryTimeoutSlashingFailed"
            )
          })

          it("should terminate the group", async () => {
            expect(await isGroupTerminated(0)).to.be.equal(true)
          })

          it("should emit RelayEntryTimedOut event", async () => {
            await expect(reportTx)
              .to.emit(randomBeacon, "RelayEntryTimedOut")
              .withArgs(1, 0)
          })

          it("should retry current relay request", async () => {
            // We expect the same request ID because this is a retry.
            // Group ID is `1` because we take an active group from `groupsRegistry`
            // array. Group with an index `0` was terminated.
            await expect(reportTx)
              .to.emit(randomBeacon, "RelayEntryRequested")
              .withArgs(1, 1, blsData.previousEntry)

            expect(await randomBeacon.isRelayRequestInProgress()).to.be.true
          })
        }
      )

      context(
        "when a group that was supposed to submit a relay request is terminated and another group expires",
        () => {
          let tx: ContractTransaction

          before(async () => {
            await createSnapshot()

            // Create another group in a rough way just to have an active group
            // once the one handling the timed out request gets terminated.
            // This makes the request retry possible. That group will not
            // perform any signing so their public key can be arbitrary bytes.
            // Also, that group is created just after the relay request is
            // made to ensure it is not selected for signing the original request.
            await (randomBeacon as unknown as RandomBeaconStub).roughlyAddGroup(
              "0x01",
              hashUint32Array(membersIDs)
            )

            // Set a short value of group lifetime to avoid long test execution
            // if original value is used.
            const newGroupLifetime = 10
            await randomBeaconGovernance
              .connect(governance)
              .beginGroupLifetimeUpdate(newGroupLifetime)
            await helpers.time.increaseTime(params.governanceDelay)
            await randomBeaconGovernance
              .connect(governance)
              .finalizeGroupLifetimeUpdate()

            const secondGroupLifetime = await groupLifetimeOf(1)

            // Expire second group
            await mineBlocksTo(secondGroupLifetime.toNumber() + 1)

            tx = await randomBeacon.reportRelayEntryTimeout(membersIDs)
          })

          after(async () => {
            await restoreSnapshot()
          })

          it("should terminate the group", async () => {
            expect(await isGroupTerminated(0)).to.be.equal(true)
          })

          it("should not emit RelayEntryRequested", async () => {
            await expect(tx).to.not.emit(randomBeacon, "RelayEntryRequested")
          })

          it("should clean up current relay request data", async () => {
            expect(await randomBeacon.isRelayRequestInProgress()).to.be.false
          })
        }
      )

      context("when no active groups exist after timeout is reported", () => {
        let reportTx: ContractTransaction
        let slashingTx: ContractTransaction

        before(async () => {
          await createSnapshot()

          reportTx = await randomBeacon
            .connect(notifier)
            .reportRelayEntryTimeout(membersIDs)

          slashingTx = await staking.processSlashing(membersAddresses.length)
        })

        after(async () => {
          await restoreSnapshot()
        })

        it("should reward the notifier", async () => {
          await expect(reportTx)
            .to.emit(staking, "NotifierRewarded")
            .withArgs(
              notifier.address,
              constants.tokenStakingNotificationReward
                .mul(params.relayEntryTimeoutNotificationRewardMultiplier)
                .div(100)
                .mul(membersIDs.length)
            )
        })

        it("should slash the full slashing amount for all group members", async () => {
          for (let i = 0; i < membersAddresses.length; i++) {
            const stakingProvider =
              await randomBeacon.operatorToStakingProvider(membersAddresses[i])

            await expect(slashingTx)
              .to.emit(staking, "TokensSeized")
              .withArgs(
                stakingProvider,
                params.relayEntrySubmissionFailureSlashingAmount,
                false
              )
          }
        })

        it("should emit RelayEntryTimeoutSlashed event", async () => {
          await expect(reportTx)
            .to.emit(randomBeacon, "RelayEntryTimeoutSlashed")
            .withArgs(
              1,
              params.relayEntrySubmissionFailureSlashingAmount,
              membersAddresses
            )
        })

        it("should not emit RelayEntryTimeoutSlashingFailed event", async () => {
          await expect(reportTx).to.not.emit(
            randomBeacon,
            "RelayEntryTimeoutSlashingFailed"
          )
        })

        it("should terminate the group", async () => {
          expect(await isGroupTerminated(0)).to.be.equal(true)
        })

        it("should emit RelayEntryTimedOut event", async () => {
          await expect(reportTx)
            .to.emit(randomBeacon, "RelayEntryTimedOut")
            .withArgs(1, 0)
        })

        it("should clean up current relay request data", async () => {
          await expect(reportTx).to.not.emit(
            randomBeacon,
            "RelayEntryRequested"
          )
          expect(await randomBeacon.isRelayRequestInProgress()).to.be.false
        })
      })

      context(
        "when no active groups exist after timeout is reported and DKG is awaiting seed",
        () => {
          let tx: ContractTransaction

          before(async () => {
            await createSnapshot()

            // Simulate DKG is awaiting a seed.
            await randomBeacon.dkgLockState()

            tx = await randomBeacon
              .connect(notifier)
              .reportRelayEntryTimeout(membersIDs)
          })

          after(async () => {
            await restoreSnapshot()
          })

          it("should notify DKG seed timed out", async () => {
            expect(await randomBeacon.getGroupCreationState()).to.be.equal(
              dkgState.IDLE
            )
            expect(await sortitionPool.isLocked()).to.be.false
          })

          it("should emit DkgSeedTimedOut event", async () => {
            await expect(tx).to.emit(randomBeacon, "DkgSeedTimedOut")
          })
        }
      )

      // FIXME: Blocked by https://github.com/defi-wonderland/smock/issues/101
      context.skip("when token staking seize call fails", async () => {
        let tokenStakingFake: FakeContract<TokenStaking>
        let tx: Promise<ContractTransaction>

        before(async () => {
          await createSnapshot()

          tokenStakingFake = await fakeTokenStaking(randomBeacon)
          tokenStakingFake.seize.reverts("faked function revert")

          tx = randomBeacon.reportRelayEntryTimeout(membersIDs)
        })

        after(async () => {
          await restoreSnapshot()

          tokenStakingFake.seize.reset()
        })

        it("should succeed", async () => {
          await expect(tx).to.not.be.reverted
        })

        it("should emit RelayEntryTimeoutSlashingFailed", async () => {
          await expect(tx)
            .to.emit(randomBeacon, "RelayEntryTimeoutSlashingFailed")
            .withArgs(
              1,
              params.relayEntrySubmissionFailureSlashingAmount,
              membersAddresses
            )
        })
      })
    })

    context("when relay entry did not time out", () => {
      it("should revert", async () => {
        await expect(
          randomBeacon.reportRelayEntryTimeout(membersIDs)
        ).to.be.revertedWith("Relay request did not time out")
      })
    })

    context("when group members are invalid", () => {
      it("should revert", async () => {
        const invalidMembersId = [0, 1, 42]
        await expect(
          randomBeacon.reportRelayEntryTimeout(invalidMembersId)
        ).to.be.revertedWith("Invalid group members")
      })
    })
  })

  describe("reportUnauthorizedSigning", () => {
    before(async () => {
      await createSnapshot()

      await createGroup(randomBeacon, members)
      await randomBeacon.connect(requester).requestRelayEntry(ZERO_ADDRESS)
    })

    after(async () => {
      await restoreSnapshot()
    })

    context("when a group is active", () => {
      context("when provided signature is valid", () => {
        let reportTx: ContractTransaction
        let slashingTx: ContractTransaction

        before(async () => {
          await createSnapshot()

          const notifierSignature = await bls.sign(
            notifier.address,
            blsData.secretKey
          )
          reportTx = await randomBeacon
            .connect(notifier)
            .reportUnauthorizedSigning(notifierSignature, 0, membersIDs)

          slashingTx = await staking.processSlashing(membersAddresses.length)
        })

        after(async () => {
          await restoreSnapshot()
        })

        it("should terminate the group", async () => {
          expect(await isGroupTerminated(0)).to.be.equal(true)
        })

        it("should reward the notifier", async () => {
          await expect(reportTx)
            .to.emit(staking, "NotifierRewarded")
            .withArgs(
              notifier.address,
              constants.tokenStakingNotificationReward
                .mul(params.unauthorizedSigningNotificationRewardMultiplier)
                .div(100)
                .mul(membersIDs.length)
            )
        })

        it("should slash unauthorized signing slashing amount for all group members", async () => {
          for (let i = 0; i < membersAddresses.length; i++) {
            const stakingProvider =
              await randomBeacon.operatorToStakingProvider(membersAddresses[i])

            await expect(slashingTx)
              .to.emit(staking, "TokensSeized")
              .withArgs(
                stakingProvider,
                params.unauthorizedSigningSlashingAmount,
                false
              )
          }
        })

        it("should emit unauthorized signing slashing event", async () => {
          await expect(reportTx)
            .to.emit(randomBeacon, "UnauthorizedSigningSlashed")
            .withArgs(
              0,
              params.unauthorizedSigningSlashingAmount,
              membersAddresses
            )
        })

        it("should not emit UnauthorizedSigningSlashingFailed", async () => {
          await expect(reportTx).to.not.emit(
            randomBeacon,
            "UnauthorizedSigningSlashingFailed"
          )
        })
      })

      // FIXME: Blocked by https://github.com/defi-wonderland/smock/issues/101
      context.skip("when token staking seize call fails", async () => {
        let tokenStakingFake: FakeContract<TokenStaking>
        let tx: Promise<ContractTransaction>

        before(async () => {
          await createSnapshot()

          tokenStakingFake = await fakeTokenStaking(randomBeacon)
          tokenStakingFake.seize.reverts("faked function revert")

          const notifierSignature = await bls.sign(
            notifier.address,
            blsData.secretKey
          )
          tx = randomBeacon
            .connect(notifier)
            .reportUnauthorizedSigning(notifierSignature, 0, membersIDs)
        })

        after(async () => {
          await restoreSnapshot()

          tokenStakingFake.seize.reset()
        })

        it("should succeed", async () => {
          await expect(tx).to.not.be.reverted
        })

        it("should emit UnauthorizedSigningSlashingFailed", async () => {
          await expect(tx)
            .to.emit(randomBeacon, "UnauthorizedSigningSlashingFailed")
            .withArgs(0, to1e18(100000), membersAddresses)
        })
      })
    })

    context("when group is terminated", () => {
      before(async () => {
        await createSnapshot()

        await mineBlocks(
          params.relayEntrySoftTimeout + params.relayEntryHardTimeout
        )

        await (
          randomBeacon as unknown as RandomBeaconStub
        ).roughlyTerminateGroup(0)
      })

      after(async () => {
        await restoreSnapshot()
      })

      it("should revert", async () => {
        const notifierSignature = await bls.sign(
          notifier.address,
          blsData.secretKey
        )

        await expect(
          randomBeacon
            .connect(notifier)
            .reportUnauthorizedSigning(notifierSignature, 0, membersIDs)
        ).to.be.revertedWith("Group cannot be terminated")
      })
    })

    context("when provided signature is invalid", () => {
      it("should revert", async () => {
        // the valid key is 123 instead of 42
        const notifierSignature = await bls.sign(notifier.address, 42)
        await expect(
          randomBeacon
            .connect(notifier)
            .reportUnauthorizedSigning(notifierSignature, 0, membersIDs)
        ).to.be.revertedWith("Invalid signature")
      })
    })

    context("when group members are invalid", () => {
      it("should revert", async () => {
        const notifierSignature = await bls.sign(notifier.address, 42)
        const invalidMembersId = [0, 1, 42]
        await expect(
          randomBeacon
            .connect(notifier)
            .reportUnauthorizedSigning(notifierSignature, 0, invalidMembersId)
        ).to.be.revertedWith("Invalid group members")
      })
    })
  })

  describe("calculateSlashingAmount", () => {
    before(async () => {
      await relayStub.setTimeouts(
        params.relayEntrySoftTimeout,
        params.relayEntryHardTimeout
      )
      await relayStub.setRelayEntrySubmissionFailureSlashingAmount(
        params.relayEntrySubmissionFailureSlashingAmount
      )
      await relayStub.setCurrentRequestStartBlock()
    })

    beforeEach(async () => {
      await createSnapshot()
    })

    afterEach(async () => {
      await restoreSnapshot()
    })

    context("when a soft timeout has been exceeded by one block", () => {
      it("should return a correct slashing amount", async () => {
        await mineBlocks(params.relayEntrySoftTimeout + 1)

        // We exceeded the soft timeout by `1`
        // slashing amount: 1 * 1000e18 / 100 = 10e18
        expect(
          await relayStub.callStatic.calculateSlashingAmount()
        ).to.be.equal(BigNumber.from("10000000000000000000"))
      })
    })

    context(
      "when soft timeout has been exceeded by the number of blocks equal to the hard timeout",
      () => {
        it("should return a correct slashing amount", async () => {
          await mineBlocks(
            params.relayEntrySoftTimeout + params.relayEntryHardTimeout
          )

          // We exceeded the soft timeout by `100`
          // slashing amount: 100 * 1000e18 / 100 = 1000e18
          expect(
            await relayStub.callStatic.calculateSlashingAmount()
          ).to.be.equal(BigNumber.from("1000000000000000000000"))
        })
      }
    )

    context(
      "when soft timeout has been exceeded by the number of blocks bigger than the hard timeout",
      () => {
        it("should return a correct slashing factor", async () => {
          await mineBlocks(
            params.relayEntrySoftTimeout + params.relayEntryHardTimeout + 1
          )

          // We are exceeded the soft timeout by a value bigger than the
          // hard timeout. In that case the maximum value (100%) of the slashing
          // amount should be returned.
          expect(
            await relayStub.callStatic.calculateSlashingAmount()
          ).to.be.equal(BigNumber.from("1000000000000000000000"))
        })
      }
    )
  })

  describe("notifyOperatorInactivity", () => {
    const groupId = 0
    const emptySignatures = "0x00"
    const emptyMemberIndices: number[] = []
    // Use 31 element `inactiveMembersIndices` array to simulate the most gas
    // expensive real-world case. If group size is 64, the required threshold
    // is 33 so we assume 31 operators at most will be marked as ineligible
    // during a single `notifyOperatorInactivity` call.
    const subsequentInactiveMembersIndices = Array.from(
      Array(31),
      (_, i) => i + 1
    )
    const nonSubsequentInactiveMembersIndices = [2, 5, 7, 23, 56]
    const groupThreshold = 33

    let group: Groups.GroupStructOutput

    before(async () => {
      await createSnapshot()

      await createGroup(randomBeacon, members)
      group = await randomBeacon["getGroup(uint64)"](groupId)
    })

    after(async () => {
      await restoreSnapshot()
    })

    context("when passed nonce is valid", () => {
      context("when group is active and non-terminated", () => {
        context("when inactive members indices are correct", () => {
          context("when signatures array is correct", () => {
            context("when signing members indices are correct", () => {
              context("when all signatures are correct", () => {
                context("when claim sender signed the claim", () => {
                  const assertNotifyInactivitySucceed = async (
                    inactiveMembersIndices: number[],
                    signaturesCount: number,
                    modifySignatures: (signatures: string) => string,
                    modifySigningMemberIndices: (
                      signingMemberIndices: number[]
                    ) => number[]
                  ) => {
                    let tx: ContractTransaction
                    let initialNonce: BigNumber
                    let initialNotifierBalance: BigNumber
                    let claimSender: SignerWithAddress

                    before(async () => {
                      await createSnapshot()

                      // Assume claim sender is the first signing member.
                      claimSender = members[0].signer

                      initialNonce = await randomBeacon.inactivityClaimNonce(
                        groupId
                      )

                      initialNotifierBalance = await provider.getBalance(
                        claimSender.address
                      )

                      const { signatures, signingMembersIndices } =
                        await signOperatorInactivityClaim(
                          members,
                          0,
                          group.groupPubKey,
                          inactiveMembersIndices,
                          signaturesCount
                        )

                      tx = await randomBeacon
                        .connect(claimSender)
                        .notifyOperatorInactivity(
                          {
                            groupId,
                            inactiveMembersIndices,
                            signatures: modifySignatures(signatures),
                            signingMembersIndices: modifySigningMemberIndices(
                              signingMembersIndices
                            ),
                          },
                          0,
                          membersIDs
                        )
                    })

                    after(async () => {
                      await restoreSnapshot()
                    })

                    it("should increment inactivity claim nonce for the group", async () => {
                      expect(
                        await randomBeacon.inactivityClaimNonce(groupId)
                      ).to.be.equal(initialNonce.add(1))
                    })

                    it("should emit InactivityClaimed event", async () => {
                      await expect(tx)
                        .to.emit(randomBeacon, "InactivityClaimed")
                        .withArgs(
                          groupId,
                          initialNonce.toNumber(),
                          claimSender.address
                        )
                    })

                    it("should ban sortition pool rewards for inactive operators", async () => {
                      const now = await helpers.time.lastBlockTime()
                      const expectedUntil =
                        now + params.sortitionPoolRewardsBanDuration

                      const expectedIneligibleMembersIDs =
                        inactiveMembersIndices.map((i) => membersIDs[i - 1])

                      await expect(tx)
                        .to.emit(sortitionPool, "IneligibleForRewards")
                        .withArgs(expectedIneligibleMembersIDs, expectedUntil)
                    })

                    it("should refund ETH", async () => {
                      const postNotifierBalance = await provider.getBalance(
                        await claimSender.getAddress()
                      )
                      const diff = postNotifierBalance.sub(
                        initialNotifierBalance
                      )
                      expect(diff).to.be.gt(0)
                      expect(diff).to.be.lt(
                        ethers.utils.parseUnits("1000000", "gwei") // 0,001 ETH
                      )
                    })
                  }

                  context(
                    "when there are multiple subsequent inactive members indices",
                    async () => {
                      await assertNotifyInactivitySucceed(
                        subsequentInactiveMembersIndices,
                        groupThreshold,
                        (signatures) => signatures,
                        (signingMembersIndices) => signingMembersIndices
                      )
                    }
                  )

                  context(
                    "when there is only one inactive member index",
                    async () => {
                      await assertNotifyInactivitySucceed(
                        [32],
                        groupThreshold,
                        (signatures) => signatures,
                        (signingMembersIndices) => signingMembersIndices
                      )
                    }
                  )

                  context(
                    "when there are multiple non-subsequent inactive members indices",
                    async () => {
                      await assertNotifyInactivitySucceed(
                        nonSubsequentInactiveMembersIndices,
                        groupThreshold,
                        (signatures) => signatures,
                        (signingMembersIndices) => signingMembersIndices
                      )
                    }
                  )

                  context(
                    "when there are multiple non-subsequent signing members indices",
                    async () => {
                      const newSigningMembersIndices = [
                        1, 5, 8, 11, 14, 15, 18, 20, 22, 24, 25, 27, 29, 30, 31,
                        33, 38, 39, 41, 42, 44, 47, 48, 49, 51, 53, 55, 56, 57,
                        59, 61, 62, 64,
                      ]

                      // we cut the first 2 characters to get rid of "0x" and
                      // then return signature on arbitrary position - each
                      // signature has 65 bytes so 130 characters
                      const getSignature = (
                        signatures: string,
                        index: number
                      ) =>
                        signatures
                          .slice(2)
                          .slice(130 * index, 130 * index + 130)

                      const modifySignatures = (signatures: string) => {
                        let newSignatures = "0x"

                        for (
                          let i = 0;
                          i < newSigningMembersIndices.length;
                          i++
                        ) {
                          const newSigningMemberIndex =
                            newSigningMembersIndices[i]
                          newSignatures += getSignature(
                            signatures,
                            newSigningMemberIndex - 1
                          )
                        }

                        return newSignatures
                      }

                      await assertNotifyInactivitySucceed(
                        subsequentInactiveMembersIndices,
                        // Make more signatures than needed to allow picking up
                        // arbitrary signatures.
                        64,
                        modifySignatures,
                        () => newSigningMembersIndices
                      )
                    }
                  )
                })

                context(
                  "when claim sender did not sign the claim",
                  async () => {
                    it("should revert", async () => {
                      const { signatures, signingMembersIndices } =
                        await signOperatorInactivityClaim(
                          members,
                          0,
                          group.groupPubKey,
                          subsequentInactiveMembersIndices,
                          groupThreshold
                        )

                      const claimSender = thirdParty

                      await expect(
                        randomBeacon
                          .connect(claimSender)
                          .notifyOperatorInactivity(
                            {
                              groupId,
                              inactiveMembersIndices:
                                subsequentInactiveMembersIndices,
                              signatures,
                              signingMembersIndices,
                            },
                            0,
                            membersIDs
                          )
                      ).to.be.revertedWith("Sender must be claim signer")
                    })
                  }
                )
              })

              context("when one of the signatures is incorrect", () => {
                const assertInvalidSignature = async (
                  invalidSignature: string
                ) => {
                  // The 32 signers sign correct parameters. Invalid signature
                  // is expected to be provided by signer 33.
                  const { signatures, signingMembersIndices } =
                    await signOperatorInactivityClaim(
                      members,
                      0,
                      group.groupPubKey,
                      subsequentInactiveMembersIndices,
                      groupThreshold - 1
                    )

                  await expect(
                    randomBeacon.notifyOperatorInactivity(
                      {
                        groupId,
                        inactiveMembersIndices:
                          subsequentInactiveMembersIndices,
                        // Slice removes `0x` prefix from wrong signature.
                        signatures: signatures + invalidSignature.slice(2),
                        signingMembersIndices: [...signingMembersIndices, 33],
                      },
                      0,
                      membersIDs
                    )
                  ).to.be.revertedWith("Invalid signature")
                }

                context(
                  "when one of the signatures signed the wrong nonce",
                  () => {
                    it("should revert", async () => {
                      // Signer 33 signs wrong nonce.
                      const invalidSignature = (
                        await signOperatorInactivityClaim(
                          [members[32]],
                          1,
                          group.groupPubKey,
                          subsequentInactiveMembersIndices,
                          1
                        )
                      ).signatures

                      await assertInvalidSignature(invalidSignature)
                    })
                  }
                )

                context(
                  "when one of the signatures signed the wrong group public key",
                  () => {
                    it("should revert", async () => {
                      // Signer 33 signs wrong group public key.
                      const invalidSignature = (
                        await signOperatorInactivityClaim(
                          [members[32]],
                          0,
                          "0x010203",
                          subsequentInactiveMembersIndices,
                          1
                        )
                      ).signatures

                      await assertInvalidSignature(invalidSignature)
                    })
                  }
                )

                context(
                  "when one of the signatures signed the wrong inactive group members indices",
                  () => {
                    it("should revert", async () => {
                      // Signer 33 signs wrong inactive group members indices.
                      const invalidSignature = (
                        await signOperatorInactivityClaim(
                          [members[32]],
                          0,
                          group.groupPubKey,
                          [1, 2, 3, 4, 5, 6, 7, 8],
                          1
                        )
                      ).signatures

                      await assertInvalidSignature(invalidSignature)
                    })
                  }
                )
              })
            })

            context("when signing members indices are incorrect", () => {
              context(
                "when signing members indices count is different than signatures count",
                () => {
                  it("should revert", async () => {
                    const { signatures, signingMembersIndices } =
                      await signOperatorInactivityClaim(
                        members,
                        0,
                        group.groupPubKey,
                        subsequentInactiveMembersIndices,
                        groupThreshold
                      )

                    await expect(
                      randomBeacon.notifyOperatorInactivity(
                        {
                          groupId,
                          inactiveMembersIndices:
                            subsequentInactiveMembersIndices,
                          signatures,
                          // Remove the first signing member index
                          signingMembersIndices: signingMembersIndices.slice(1),
                        },
                        0,
                        membersIDs
                      )
                    ).to.be.revertedWith("Unexpected signatures count")
                  })
                }
              )

              context("when first signing member index is zero", () => {
                it("should revert", async () => {
                  const { signatures, signingMembersIndices } =
                    await signOperatorInactivityClaim(
                      members,
                      0,
                      group.groupPubKey,
                      subsequentInactiveMembersIndices,
                      groupThreshold
                    )

                  signingMembersIndices[0] = 0

                  await expect(
                    randomBeacon.notifyOperatorInactivity(
                      {
                        groupId,
                        inactiveMembersIndices:
                          subsequentInactiveMembersIndices,
                        signatures,
                        signingMembersIndices,
                      },
                      0,
                      membersIDs
                    )
                  ).to.be.revertedWith("Corrupted members indices")
                })
              })

              context(
                "when last signing member index is bigger than group size",
                () => {
                  it("should revert", async () => {
                    const { signatures, signingMembersIndices } =
                      await signOperatorInactivityClaim(
                        members,
                        0,
                        group.groupPubKey,
                        subsequentInactiveMembersIndices,
                        groupThreshold
                      )

                    signingMembersIndices[signingMembersIndices.length - 1] = 65

                    await expect(
                      randomBeacon.notifyOperatorInactivity(
                        {
                          groupId,
                          inactiveMembersIndices:
                            subsequentInactiveMembersIndices,
                          signatures,
                          signingMembersIndices,
                        },
                        0,
                        membersIDs
                      )
                    ).to.be.revertedWith("Corrupted members indices")
                  })
                }
              )

              context(
                "when signing members indices are not ordered in ascending order",
                () => {
                  it("should revert", async () => {
                    const { signatures, signingMembersIndices } =
                      await signOperatorInactivityClaim(
                        members,
                        0,
                        group.groupPubKey,
                        subsequentInactiveMembersIndices,
                        groupThreshold
                      )

                    // eslint-disable-next-line prefer-destructuring
                    signingMembersIndices[10] = signingMembersIndices[11]

                    await expect(
                      randomBeacon.notifyOperatorInactivity(
                        {
                          groupId,
                          inactiveMembersIndices:
                            subsequentInactiveMembersIndices,
                          signatures,
                          signingMembersIndices,
                        },
                        0,
                        membersIDs
                      )
                    ).to.be.revertedWith("Corrupted members indices")
                  })
                }
              )
            })
          })

          context("when signatures array is incorrect", () => {
            context("when signatures count is zero", () => {
              it("should revert", async () => {
                const signatures = "0x"

                await expect(
                  randomBeacon.notifyOperatorInactivity(
                    {
                      groupId,
                      inactiveMembersIndices: subsequentInactiveMembersIndices,
                      signatures,
                      signingMembersIndices: emptyMemberIndices,
                    },
                    0,
                    membersIDs
                  )
                ).to.be.revertedWith("No signatures provided")
              })
            })

            context(
              "when signatures count is not divisible by signature byte size",
              () => {
                it("should revert", async () => {
                  const signatures = "0x010203"

                  await expect(
                    randomBeacon.notifyOperatorInactivity(
                      {
                        groupId,
                        inactiveMembersIndices:
                          subsequentInactiveMembersIndices,
                        signatures,
                        signingMembersIndices: emptyMemberIndices,
                      },
                      0,
                      membersIDs
                    )
                  ).to.be.revertedWith("Malformed signatures array")
                })
              }
            )

            context(
              "when signatures count is different than signing members count",
              () => {
                it("should revert", async () => {
                  const { signatures, signingMembersIndices } =
                    await signOperatorInactivityClaim(
                      members,
                      0,
                      group.groupPubKey,
                      subsequentInactiveMembersIndices,
                      groupThreshold
                    )

                  await expect(
                    randomBeacon.notifyOperatorInactivity(
                      {
                        groupId,
                        inactiveMembersIndices:
                          subsequentInactiveMembersIndices,
                        // Remove the first signature to cause a mismatch with
                        // the signing members count.
                        signatures: `0x${signatures.slice(132)}`,
                        signingMembersIndices,
                      },
                      0,
                      membersIDs
                    )
                  ).to.be.revertedWith("Unexpected signatures count")
                })
              }
            )

            context(
              "when signatures count is less than group threshold",
              () => {
                it("should revert", async () => {
                  const { signatures, signingMembersIndices } =
                    await signOperatorInactivityClaim(
                      members,
                      0,
                      group.groupPubKey,
                      subsequentInactiveMembersIndices,
                      // Provide one signature too few.
                      groupThreshold - 1
                    )

                  await expect(
                    randomBeacon.notifyOperatorInactivity(
                      {
                        groupId,
                        inactiveMembersIndices:
                          subsequentInactiveMembersIndices,
                        signatures,
                        signingMembersIndices,
                      },
                      0,
                      membersIDs
                    )
                  ).to.be.revertedWith("Too few signatures")
                })
              }
            )

            context("when signatures count is bigger than group size", () => {
              it("should revert", async () => {
                const { signatures, signingMembersIndices } =
                  await signOperatorInactivityClaim(
                    members,
                    0,
                    group.groupPubKey,
                    subsequentInactiveMembersIndices,
                    // All group signs.
                    members.length
                  )

                await expect(
                  randomBeacon.notifyOperatorInactivity(
                    {
                      groupId,
                      inactiveMembersIndices: subsequentInactiveMembersIndices,
                      // Provide one signature too much.
                      signatures: signatures + signatures.slice(2, 132),
                      signingMembersIndices: [
                        ...signingMembersIndices,
                        signingMembersIndices[0],
                      ],
                    },
                    0,
                    membersIDs
                  )
                ).to.be.revertedWith("Too many signatures")
              })
            })
          })
        })

        context("when inactive members indices are incorrect", () => {
          const assertInactiveMembersIndicesCorrupted = async (
            inactiveMembersIndices: number[]
          ) => {
            const { signatures, signingMembersIndices } =
              await signOperatorInactivityClaim(
                members,
                0,
                group.groupPubKey,
                inactiveMembersIndices,
                groupThreshold
              )

            await expect(
              randomBeacon.notifyOperatorInactivity(
                {
                  groupId,
                  inactiveMembersIndices,
                  signatures,
                  signingMembersIndices,
                },
                0,
                membersIDs
              )
            ).to.be.revertedWith("Corrupted members indices")
          }

          context("when inactive members indices count is zero", () => {
            it("should revert", async () => {
              const inactiveMembersIndices: number[] = []

              await assertInactiveMembersIndicesCorrupted(
                inactiveMembersIndices
              )
            })
          })

          context(
            "when inactive members indices count is bigger than group size",
            () => {
              it("should revert", async () => {
                const inactiveMembersIndices = Array.from(
                  Array(65),
                  (_, i) => i + 1
                )

                await assertInactiveMembersIndicesCorrupted(
                  inactiveMembersIndices
                )
              })
            }
          )

          context("when first inactive member index is zero", () => {
            it("should revert", async () => {
              const inactiveMembersIndices = Array.from(
                Array(64),
                (_, i) => i + 1
              )
              inactiveMembersIndices[0] = 0

              await assertInactiveMembersIndicesCorrupted(
                inactiveMembersIndices
              )
            })
          })

          context(
            "when last inactive member index is bigger than group size",
            () => {
              it("should revert", async () => {
                const inactiveMembersIndices = Array.from(
                  Array(64),
                  (_, i) => i + 1
                )
                inactiveMembersIndices[inactiveMembersIndices.length - 1] = 65

                await assertInactiveMembersIndicesCorrupted(
                  inactiveMembersIndices
                )
              })
            }
          )

          context(
            "when inactive members indices are not ordered in ascending order",
            () => {
              it("should revert", async () => {
                const inactiveMembersIndices = Array.from(
                  Array(64),
                  (_, i) => i + 1
                )
                // eslint-disable-next-line prefer-destructuring
                inactiveMembersIndices[10] = inactiveMembersIndices[11]

                await assertInactiveMembersIndicesCorrupted(
                  inactiveMembersIndices
                )
              })
            }
          )
        })
      })

      context("when group was active but got terminated", () => {
        before(async () => {
          await createSnapshot()

          // Simulate group was terminated.
          await (
            randomBeacon as unknown as RandomBeaconStub
          ).roughlyTerminateGroup(groupId)
        })

        after(async () => {
          await restoreSnapshot()
        })

        it("should revert", async () => {
          await expect(
            randomBeacon.notifyOperatorInactivity(
              {
                groupId,
                inactiveMembersIndices: emptyMemberIndices,
                signatures: emptySignatures,
                signingMembersIndices: emptyMemberIndices,
              },
              0,
              membersIDs
            )
          ).to.be.revertedWith("Group is not active")
        })
      })

      context("when group is expired", () => {
        before(async () => {
          await createSnapshot()

          // Set a short value of group lifetime to avoid long test execution
          // if original value is used.
          const newGroupLifetime = 10
          await randomBeaconGovernance
            .connect(governance)
            .beginGroupLifetimeUpdate(newGroupLifetime)
          await helpers.time.increaseTime(params.governanceDelay)
          await randomBeaconGovernance
            .connect(governance)
            .finalizeGroupLifetimeUpdate()

          // Simulate group was expired.
          await mineBlocks(newGroupLifetime)
        })

        after(async () => {
          await restoreSnapshot()
        })

        it("should revert", async () => {
          await expect(
            randomBeacon.notifyOperatorInactivity(
              {
                groupId,
                inactiveMembersIndices: emptyMemberIndices,
                signatures: emptySignatures,
                signingMembersIndices: emptyMemberIndices,
              },
              0,
              membersIDs
            )
          ).to.be.revertedWith("Group is not active")
        })
      })
    })

    context("when passed nonce is invalid", () => {
      it("should revert", async () => {
        await expect(
          randomBeacon.notifyOperatorInactivity(
            {
              groupId,
              inactiveMembersIndices: emptyMemberIndices,
              signatures: emptySignatures,
              signingMembersIndices: emptyMemberIndices,
            },
            1,
            membersIDs
          ) // Initial nonce is `0`.
        ).to.be.revertedWith("Invalid nonce")
      })
    })

    context("when group members are invalid", () => {
      it("should revert", async () => {
        const invalidMembersId = [0, 1, 42]
        await expect(
          randomBeacon.notifyOperatorInactivity(
            {
              groupId,
              inactiveMembersIndices: emptyMemberIndices,
              signatures: emptySignatures,
              signingMembersIndices: emptyMemberIndices,
            },
            0,
            invalidMembersId
          )
        ).to.be.revertedWith("Invalid group members")
      })
    })
  })

  async function groupLifetimeOf(groupID: BigNumberish): Promise<BigNumber> {
    const groupData = await randomBeacon.callStatic["getGroup(uint64)"](groupID)

    const { groupLifetime } = await randomBeacon.groupCreationParameters()

    return groupData.registrationBlockNumber.add(groupLifetime)
  }

  async function isGroupTerminated(groupID: BigNumberish): Promise<boolean> {
    const groupData = await randomBeacon.callStatic["getGroup(uint64)"](groupID)

    return groupData.terminated === true
  }
})
