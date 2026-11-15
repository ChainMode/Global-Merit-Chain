/**
 * Global Merit Chain (GMChain) Protocol Draft TypeScript Schema Definitions.
 *
 * Aligns single-layer coFay ownership, unbounded Nested Merit Chain derivation,
 * 1:1 OrganizationID <-> ChainId binding, natural-person Steward accountability,
 * and B_i = 0 cold-start bootstrap Merit batches.
 */

export type HumanID = `hid_${string}`;
export type OrganizationID = `org_${string}`;
export type IFayID = `ifay_${string}`;
export type CoFayID = `cofay_${string}`;
export type OpaqueRef = `gmcref_${string}`;
export type FixedDecimal = string;

export type OwnerKind = "human" | "organization";

export type OwnerRef =
  | { readonly id: HumanID; readonly kind: "human" }
  | { readonly id: OrganizationID; readonly kind: "organization" };

export interface CoFayOwnershipRecord {
  readonly cofayId: CoFayID;
  readonly owner: OwnerRef;
  readonly delegates?: readonly string[];
}

export type InitiationChannel = "Vote" | "Steward" | "InstitutionApplication";

export interface NestedMeritChainRecord {
  readonly chainId: string;
  readonly parentId: string;
  readonly domain: string;
  /** Ordered path starting at "gmc-base"; unbounded protocol depth. */
  readonly derivationPath: readonly string[];
  /** Optional 1:1 projection of FayID OrganizationID onto GMChain. */
  readonly organizationId?: OrganizationID;
  /** Accountable natural-person Stewards (HumanID required; iFay/coFay forbidden). */
  readonly stewards: readonly [HumanID, ...HumanID[]];
  /** Operational chain managers (iFay avatars); never modifies Steward accountability. */
  readonly managers?: readonly IFayID[];
  readonly initiationChannel: InitiationChannel;
  readonly createdAt: number;
}

export interface BootstrapMeritBatch {
  readonly batchId: string;
  readonly origin: "BootstrapPurchased";
  readonly opaqueRef: OpaqueRef;
  readonly amount: FixedDecimal;
  /** Immutable protocol constant: bootstrap batches have zero floor contribution. */
  readonly b: "0";
  /** Accelerated decay multiplier (>= 2; conservative = 3, neutral = 2). */
  readonly decayMultiplier: number;
  readonly influenceDurationSecs: number;
  readonly acquiredAt: number;
  readonly sourceChainId: "gmc-base";
}

export interface GovernanceVoterSlice {
  readonly ifayId: IFayID;
  readonly opaqueRef: OpaqueRef;
  readonly effectiveMerit: FixedDecimal;
}
