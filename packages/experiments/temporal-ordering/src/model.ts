export type Step = "A" | "S" | "R" | "G" | "N" | "D" | "AUDIT";

export type CasePlan = {
  case_id: string;
  ordered_events: Step[];
  deployment_transaction_sender: "writer" | "actor";
};

export type CaseManifest = {
  schema_version: "govprov.temporal_ordering_cases.v1";
  cases: CasePlan[];
};

export type RunMetadata = {
  run_id: string;
  chain_id: number;
  attestation_actor: string;
  anchor_transaction_sender: string;
  default_deployment_transaction_sender: string;
  approval_actor: string;
  required_role_at_N: string;
  deployer_role: string;
  ledger_writer_role: string;
  policy_hash: string;
  contracts: Record<"ActorRegistry" | "PolicyRegistry" | "ProvenanceRegistry" | "ApprovalRegistry" | "DeploymentRegistry", string>;
};

export type Order = { block_number: number; transaction_index: number; log_index: number };

export type RoleTransition = {
  actor: string;
  role: string;
  kind: "grant" | "revoke";
  order: Order;
  transaction_hash: string;
};

export function compareOrder(left: Order, right: Order): number {
  return left.block_number - right.block_number
    || left.transaction_index - right.transaction_index
    || left.log_index - right.log_index;
}

export function roleAt(transitions: readonly RoleTransition[], actor: string, role: string, boundary: Order): boolean {
  let held = false;
  for (const transition of [...transitions].sort((a, b) => compareOrder(a.order, b.order))) {
    if (compareOrder(transition.order, boundary) >= 0) break;
    if (transition.actor.toLowerCase() === actor.toLowerCase() && transition.role.toLowerCase() === role.toLowerCase()) {
      held = transition.kind === "grant";
    }
  }
  return held;
}

export function orderOfLog(log: { blockNumber: string; transactionIndex: string; logIndex: string }): Order {
  return {
    block_number: Number.parseInt(log.blockNumber, 16),
    transaction_index: Number.parseInt(log.transactionIndex, 16),
    log_index: Number.parseInt(log.logIndex, 16),
  };
}

export function orderOfReceipt(receipt: { blockNumber: string; transactionIndex: string }): Order {
  return {
    block_number: Number.parseInt(receipt.blockNumber, 16),
    transaction_index: Number.parseInt(receipt.transactionIndex, 16),
    log_index: -1,
  };
}

export function addressFromTopic(topic: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(topic)) throw new Error(`Invalid address topic: ${topic}`);
  return `0x${topic.slice(-40).toLowerCase()}`;
}

export function dataWord(data: string, index: number): string {
  const word = data.slice(2 + index * 64, 2 + (index + 1) * 64);
  if (word.length !== 64) throw new Error(`Missing ABI data word ${index}`);
  return `0x${word.toLowerCase()}`;
}
