/* eslint-disable @typescript-eslint/no-extra-semi */

// F-09 regression. RandomBeacon.submitRelayEntry must reject re-entry by a
// callback consumer that calls back into submitRelayEntry from
// __beaconCallback. The reentrancy guard is the inline _reentrancyStatus +
// nonReentrant modifier introduced in PR #5; see findings/F-09.md.

import { ethers, waffle, helpers } from "hardhat"
import { expect } from "chai"

import blsData from "./data/bls"
import { constants, randomBeaconDeployment } from "./fixtures"
import { createGroup } from "./utils/groups"
import { registerOperators } from "./utils/operators"

import type { RandomBeaconGovernance } from "../typechain/RandomBeaconGovernance"
import type { DeployedContracts } from "./fixtures"
import type {
  RandomBeaconStub,
  T,
  RandomBeacon,
  ReentrantBeaconConsumer,
} from "../typechain"
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"

const fixture = async () => {
  const deployment = await randomBeaconDeployment()

  const reentrantConsumer = (await (
    await ethers.getContractFactory("ReentrantBeaconConsumer")
  ).deploy(deployment.randomBeacon.address)) as ReentrantBeaconConsumer

  const contracts: DeployedContracts = {
    randomBeacon: deployment.randomBeacon,
    randomBeaconGovernance: deployment.randomBeaconGovernance,
    t: deployment.t,
    reentrantConsumer,
  }

  const signers = await registerOperators(
    contracts.randomBeacon as RandomBeacon,
    contracts.t as T,
    constants.groupSize,
    2
  )

  await createGroup(contracts.randomBeacon as RandomBeacon, signers)

  return { contracts }
}

describe("RandomBeacon - Reentrancy (F-09)", () => {
  let requester: SignerWithAddress
  let submitter: SignerWithAddress
  let governance: SignerWithAddress

  let randomBeacon: RandomBeaconStub
  let randomBeaconGovernance: RandomBeaconGovernance
  let reentrantConsumer: ReentrantBeaconConsumer

  before(async () => {
    ;[requester, submitter] = await helpers.signers.getUnnamedSigners()
    ;({ governance } = await helpers.signers.getNamedSigners())

    const { contracts } = await waffle.loadFixture(fixture)

    randomBeacon = contracts.randomBeacon as RandomBeaconStub
    randomBeaconGovernance =
      contracts.randomBeaconGovernance as RandomBeaconGovernance
    reentrantConsumer = (
      contracts as DeployedContracts & {
        reentrantConsumer: ReentrantBeaconConsumer
      }
    ).reentrantConsumer

    await randomBeaconGovernance
      .connect(governance)
      .setRequesterAuthorization(requester.address, true)
  })

  context("when a malicious consumer re-enters submitRelayEntry", () => {
    it("rejects the re-entry and lets the outer submission succeed", async () => {
      await randomBeacon
        .connect(requester)
        .requestRelayEntry(reentrantConsumer.address)

      const outerTx = await randomBeacon
        .connect(submitter)
        ["submitRelayEntry(bytes)"](blsData.groupSignature)

      // Outer relay-entry submission completes successfully.
      const receipt = await outerTx.wait()
      expect(receipt.status).to.equal(1)

      // Callback was actually invoked (so we exercised the modifier path).
      expect(await reentrantConsumer.reentryAttempted()).to.equal(true)

      // Inner re-entry into submitRelayEntry was rejected by the nonReentrant
      // modifier. Reverts trip the consumer's internal try-catch and flip
      // this flag to true.
      expect(await reentrantConsumer.reentryRejected()).to.equal(true)
    })
  })
})
