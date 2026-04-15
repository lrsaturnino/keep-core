/**
 * Augments generated TokenStaking types with methods present on deployed
 * TokenStaking variants used by random-beacon tests.
 */
import type { BigNumberish, ContractTransaction } from "ethers"
import type { CallOverrides } from "@ethersproject/contracts"

declare module "../typechain/TokenStaking" {
  export interface TokenStaking {
    stake(
      stakingProvider: string,
      beneficiary: string,
      authorizer: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>

    approveApplication(
      application: string,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>

    increaseAuthorization(
      stakingProvider: string,
      application: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>

    topUp(
      stakingProvider: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>

    processSlashing(
      count: BigNumberish,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>

    "requestAuthorizationDecrease(address,address,uint96)"(
      stakingProvider: string,
      application: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<ContractTransaction>
  }
}
