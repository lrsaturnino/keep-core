/* eslint-disable @typescript-eslint/no-extra-semi */

// Storage-layout regression tests for RandomBeacon.
//
// F-09 (inline reentrancy guard) introduced a new private storage variable
// `_reentrancyStatus`, initialised to 1 in the constructor. RandomBeacon is
// a non-proxy contract (deployed via `hardhat-deploy`'s plain
// `deployments.deploy`, see deploy/04_deploy_random_beacon.ts), so storage
// collisions don't apply -- but the *presence* and *initial value* of
// `_reentrancyStatus` are load-bearing for F-09's correctness. These tests
// pin both.

import { artifacts, ethers, waffle } from "hardhat"
import { expect } from "chai"

import { randomBeaconDeployment } from "./fixtures"

import type { RandomBeaconStub } from "../typechain"
import type { DeployedContracts } from "./fixtures"

type StorageEntry = {
  astId: number
  contract: string
  label: string
  offset: number
  slot: string
  type: string
}

async function getRandomBeaconStorageLayout(): Promise<StorageEntry[]> {
  const fullyQualifiedName = "contracts/RandomBeacon.sol:RandomBeacon"
  const buildInfo = await artifacts.getBuildInfo(fullyQualifiedName)
  if (!buildInfo) {
    throw new Error(
      `no build-info for ${fullyQualifiedName} -- ensure storageLayout is in ` +
        "outputSelection (see hardhat.config.ts)"
    )
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const contracts = buildInfo.output.contracts as any
  const layout =
    contracts["contracts/RandomBeacon.sol"].RandomBeacon.storageLayout
  if (!layout) {
    throw new Error(
      "RandomBeacon storageLayout missing from build-info -- check that the " +
        "Solidity compiler outputSelection includes 'storageLayout'"
    )
  }
  return layout.storage as StorageEntry[]
}

describe("RandomBeacon - Storage Layout", () => {
  let randomBeacon: RandomBeaconStub

  before(async () => {
    const { contracts } = await waffle.loadFixture(async () => {
      const deployment = await randomBeaconDeployment()
      const c: DeployedContracts = {
        randomBeacon: deployment.randomBeacon,
      }
      return { contracts: c }
    })
    randomBeacon = contracts.randomBeacon as RandomBeaconStub
  })

  describe("_reentrancyStatus (F-09)", () => {
    it("is declared on RandomBeacon as a uint256", async () => {
      const storage = await getRandomBeaconStorageLayout()
      const entry = storage.find((e) => e.label === "_reentrancyStatus")

      expect(
        entry,
        "F-09 regression: _reentrancyStatus storage variable missing from " +
          "RandomBeacon -- the inline reentrancy guard cannot work without it"
      ).to.not.equal(undefined)
      expect(entry!.contract).to.equal(
        "contracts/RandomBeacon.sol:RandomBeacon"
      )
      expect(entry!.type).to.match(/^t_uint256$/)
    })

    it("is initialised to 1 by the constructor (cold-SSTORE optimisation)", async () => {
      const storage = await getRandomBeaconStorageLayout()
      const entry = storage.find((e) => e.label === "_reentrancyStatus")!
      const raw = await ethers.provider.getStorageAt(
        randomBeacon.address,
        ethers.BigNumber.from(entry.slot)
      )
      expect(
        ethers.BigNumber.from(raw).toNumber(),
        "F-09 regression: _reentrancyStatus must be initialised to 1 in the " +
          "constructor. Initialising to 0 turns the first submitRelayEntry " +
          "into a cold SSTORE (warm cost is the whole point of the 1/2 " +
          "scheme; see findings/F-09.md)."
      ).to.equal(1)
    })
  })

  describe("_relayEntrySubmissionGasOffset (F-09 reimbursement)", () => {
    // The offset was raised from 11_250 to 13_450 to compensate for the
    // nonReentrant exit SSTORE. Reading the slot directly avoids the gas-
    // accounting fragility of a refund-vs-gasCost test while still catching
    // the exact regression we care about: the offset getting trimmed.
    it("is initialised to 13_450 by the constructor", async () => {
      const storage = await getRandomBeaconStorageLayout()
      const entry = storage.find(
        (e) => e.label === "_relayEntrySubmissionGasOffset"
      )!
      expect(
        entry,
        "_relayEntrySubmissionGasOffset missing from storage layout"
      ).to.not.equal(undefined)

      const raw = await ethers.provider.getStorageAt(
        randomBeacon.address,
        ethers.BigNumber.from(entry.slot)
      )
      expect(
        ethers.BigNumber.from(raw).toNumber(),
        "F-09 regression: _relayEntrySubmissionGasOffset must be 13_450 to " +
          "fully reimburse the nonReentrant exit SSTORE. Reverting to 11_250 " +
          "leaves the submitter under-paid by ~2200 gas per relay entry. If " +
          "the modifier overhead has changed, re-measure and update both the " +
          "constant in RandomBeacon.sol and this test."
      ).to.equal(13_450)
    })
  })

  describe("snapshot of security-critical storage labels", () => {
    // Pin the existence of variables whose accidental removal or rename would
    // silently break a security-relevant invariant. Pinning labels rather than
    // slot numbers keeps the test stable under benign reordering while still
    // catching the failure mode that matters: an entry just disappearing.
    const criticalLabels = [
      "_reentrancyStatus", // F-09 inline reentrancy guard
      "_relayEntrySubmissionGasOffset", // F-09 gas-reimbursement offset
      "_callbackGasLimit", // Callback gas budget (DoS bound)
      "authorizedRequesters", // requester allowlist
      "sortitionPool", // sortition source
      "staking", // slashing target
    ]

    it("contains every label in the critical list", async () => {
      const storage = await getRandomBeaconStorageLayout()
      const labels = new Set(storage.map((e) => e.label))
      criticalLabels.forEach((label) => {
        expect(
          labels.has(label),
          `storage label '${label}' missing from RandomBeacon layout -- if ` +
            "this was intentional, update the snapshot in " +
            "test/RandomBeacon.StorageLayout.test.ts and confirm no caller " +
            "depends on this storage"
        ).to.equal(true)
      })
    })
  })
})
