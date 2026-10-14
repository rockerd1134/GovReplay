import { readFileSync } from "node:fs";
import { join } from "node:path";
import { addressFromTopic, compareOrder, dataWord, orderOfLog, orderOfReceipt, roleAt, type Order, type RoleTransition, type RunMetadata } from "./model.ts";
import type { CaseHashes } from "./seglTemporal.ts";

const TOPICS = {
  actorRegistered: "0xe72af0c912d9286e10fec1c7b39d5e47e7e6e50e5b3ccc574f4e9054e2a76b00",
  actorSuspended: "0xb83e0db493b6045f22d00c21268b0fd9a7b171b82da8d31684d95da40a5c8ee3",
  actorResumed: "0xeaffcb9a8c7f7becd07541b154b8cd84deb0c9772be5d1401e7604fdafe1af07",
  actorRevoked: "0x8c5121cc5858b0b4800b127f9356228baace1fedaab81d516c0ef4754a31e097",
  roleGranted: "0xd5090a59641f85978fcc28a444d860372df8fdf532ac5c060574aed314562bcc",
  roleRevoked: "0xc2d3e4d32be7db15596c9b91f540936d89b00c622c653cbb9d21cd27ce1fd6a9",
  anchor: "0xc1217c9cfa3cbb1f983a6359b44567166866486c25fe926cbd27286443da62aa",
  deployment: "0x37ce151b681135b03e92af6c749ed6ac8ba6554ecd2a112f3defba453d9fa6a0",
  approval: "0x4e053f46d7e15b95c3586c3b814aaa389a1498293f50c884f06b3b5007703469",
  approvalRevoked: "0x47381c0825764d0139447f277b3aadc48793e3ba0fe827c90757539dd5bd46e8",
  policyRegistered: "0x157737dba032096caa5fc8e425c037af9a71f67fe9949bc1413d420b82b246cc",
} as const;

export type RpcLog = {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionIndex: string;
  logIndex: string;
  transactionHash: string;
};

export type Receipt = {
  status: string;
  transactionHash: string;
  blockNumber: string;
  transactionIndex: string;
  from: string;
  to: string | null;
  logs: RpcLog[];
  gasUsed: string;
};

export type BesuObservation = {
  rpc_url: string;
  receipts: Array<{ case_id: string; step: string; receipt: Receipt }>;
  actor_logs: RpcLog[];
  role_transitions: RoleTransition[];
  policy_logs: RpcLog[];
  approval_logs: RpcLog[];
};

export type BesuReplay = {
  write_N: "accepted" | "reverted";
  write_D: "accepted" | "reverted";
  verdict: "PASS" | "FAIL" | "NOT_APPLICABLE";
  failure_boundary: "N" | "D" | null;
  authority_at_N: boolean;
  authority_at_D: boolean;
  policy_at_D: boolean;
  approval_at_D: boolean;
  N_order: Order;
  D_order: Order;
  N_sender: string;
  D_sender: string;
  D_revert_reason: string | null;
  D_source_level_cause: string | null;
};

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!response.ok) throw new Error(`RPC ${method} HTTP ${response.status}`);
  const body = await response.json() as { result?: T; error?: { message: string } };
  if (body.error !== undefined) throw new Error(`RPC ${method}: ${body.error.message}`);
  if (body.result === undefined || body.result === null) throw new Error(`RPC ${method} returned no result`);
  return body.result;
}

async function logsForRun(url: string, address: string, firstBlock: number, lastBlock: number): Promise<RpcLog[]> {
  const logs: RpcLog[] = [];
  for (let from = firstBlock; from <= lastBlock; from += 512) {
    const through = Math.min(lastBlock, from + 511);
    logs.push(...await rpc<RpcLog[]>(url, "eth_getLogs", [{ address,
      fromBlock: `0x${from.toString(16)}`, toBlock: `0x${through.toString(16)}` }]));
  }
  return logs;
}

function jsonl<T>(path: string): T[] {
  return readFileSync(path, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as T);
}

function compactReceipt(receipt: Receipt): Receipt {
  return {
    status: receipt.status,
    transactionHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber,
    transactionIndex: receipt.transactionIndex,
    from: receipt.from,
    to: receipt.to,
    gasUsed: receipt.gasUsed,
    logs: receipt.logs.map((log) => ({
      address: log.address,
      topics: log.topics,
      data: log.data,
      blockNumber: log.blockNumber,
      transactionIndex: log.transactionIndex,
      logIndex: log.logIndex,
      transactionHash: log.transactionHash,
    })),
  };
}

export async function loadBesuObservation(runRoot: string, meta: RunMetadata, rpcUrl = "http://127.0.0.1:8545"): Promise<BesuObservation> {
  const chainId = await rpc<string>(rpcUrl, "eth_chainId", []);
  if (Number.parseInt(chainId, 16) !== meta.chain_id) throw new Error(`Wrong Besu chain: ${chainId}`);
  const rows = jsonl<{ case_id: string; step: string; receipt_file: string }>(join(runRoot, "transactions.jsonl"));
  const receipts: BesuObservation["receipts"] = [];
  for (const row of rows) {
    const saved = JSON.parse(readFileSync(join(runRoot, row.receipt_file), "utf8")) as Receipt;
    if (!/^0x[0-9a-fA-F]{64}$/.test(saved.transactionHash)) throw new Error(`Missing transaction hash: ${row.case_id}/${row.step}`);
    const fetched = await rpc<Receipt>(rpcUrl, "eth_getTransactionReceipt", [saved.transactionHash]);
    if (fetched.status !== saved.status || fetched.blockNumber !== saved.blockNumber || fetched.transactionIndex !== saved.transactionIndex
      || fetched.logs.length !== saved.logs.length) {
      throw new Error(`Saved receipt disagrees with Besu RPC: ${row.case_id}/${row.step}`);
    }
    receipts.push({ case_id: row.case_id, step: row.step, receipt: compactReceipt(fetched) });
  }
  const blocks = receipts.map(row => Number.parseInt(row.receipt.blockNumber, 16));
  if (!blocks.length) throw new Error("Run has no receipts");
  // Fresh deployment precedes the first setup receipt by only the deployment
  // script's bounded setup transactions. Include a margin for those logs and
  // page within the Besu dev RPC's maximum log-query range.
  const firstBlock = Math.max(0, Math.min(...blocks) - 256);
  const lastBlock = Math.max(...blocks);
  const [actorLogs, policyLogs, approvalLogs] = await Promise.all([
    logsForRun(rpcUrl, meta.contracts.ActorRegistry, firstBlock, lastBlock),
    logsForRun(rpcUrl, meta.contracts.PolicyRegistry, firstBlock, lastBlock),
    logsForRun(rpcUrl, meta.contracts.ApprovalRegistry, firstBlock, lastBlock),
  ]);
  const roleTransitions: RoleTransition[] = actorLogs
    .filter((log) => log.topics[0] === TOPICS.roleGranted || log.topics[0] === TOPICS.roleRevoked)
    .map((log) => ({
      actor: addressFromTopic(log.topics[1]!),
      role: log.topics[2]!.toLowerCase(),
      kind: log.topics[0] === TOPICS.roleGranted ? "grant" as const : "revoke" as const,
      order: orderOfLog(log),
      transaction_hash: log.transactionHash,
    }));
  roleTransitions.sort((a, b) => compareOrder(a.order, b.order));
  return { rpc_url: rpcUrl, receipts, actor_logs: actorLogs, role_transitions: roleTransitions, policy_logs: policyLogs, approval_logs: approvalLogs };
}

function receiptFor(observation: BesuObservation, caseId: string, step: string): Receipt {
  const match = observation.receipts.find((row) => row.case_id === caseId && row.step === step);
  if (match === undefined) throw new Error(`No ${step} receipt for ${caseId}`);
  return match.receipt;
}

function eventInReceipt(receipt: Receipt, topic0: string, topic1: string): RpcLog | undefined {
  return receipt.logs.find((log) => log.topics[0]?.toLowerCase() === topic0 && log.topics[1]?.toLowerCase() === topic1.toLowerCase());
}

function actorActiveAt(logs: readonly RpcLog[], actor: string, boundary: Order): boolean {
  let active = false;
  for (const log of [...logs].sort((left, right) => compareOrder(orderOfLog(left), orderOfLog(right)))) {
    if (compareOrder(orderOfLog(log), boundary) >= 0) break;
    if (log.topics[1] === undefined || addressFromTopic(log.topics[1]) !== actor.toLowerCase()) continue;
    if (log.topics[0] === TOPICS.actorRegistered || log.topics[0] === TOPICS.actorResumed) active = true;
    if (log.topics[0] === TOPICS.actorSuspended || log.topics[0] === TOPICS.actorRevoked) active = false;
  }
  return active;
}

export function verifyBesuCase(observation: BesuObservation, meta: RunMetadata, hashes: CaseHashes): BesuReplay {
  const anchorReceipt = receiptFor(observation, hashes.case_id, "anchor_N");
  const deploymentReceipt = receiptFor(observation, hashes.case_id, "deployment_D");
  const anchor = eventInReceipt(anchorReceipt, TOPICS.anchor, hashes.action_hash);
  if (anchorReceipt.status === "0x1" && anchor === undefined) throw new Error(`Accepted N lacks attestation event: ${hashes.case_id}`);
  const deployment = eventInReceipt(deploymentReceipt, TOPICS.deployment, hashes.deployment_id_hash);
  if (deploymentReceipt.status === "0x1" && deployment === undefined) throw new Error(`Accepted D lacks deployment event: ${hashes.case_id}`);
  if (anchor !== undefined && addressFromTopic(dataWord(anchor.data, 0)) !== meta.attestation_actor.toLowerCase()) {
    throw new Error(`Anchored actor differs from manifest: ${hashes.case_id}`);
  }
  const nOrder = anchor === undefined ? orderOfReceipt(anchorReceipt) : orderOfLog(anchor);
  const dOrder = deployment === undefined ? orderOfReceipt(deploymentReceipt) : orderOfLog(deployment);
  const authorityN = actorActiveAt(observation.actor_logs, meta.attestation_actor, nOrder)
    && roleAt(observation.role_transitions, meta.attestation_actor, meta.deployer_role, nOrder);
  const dSender = deploymentReceipt.from.toLowerCase();
  const authorityD = actorActiveAt(observation.actor_logs, dSender, dOrder)
    && (roleAt(observation.role_transitions, dSender, meta.deployer_role, dOrder)
      || roleAt(observation.role_transitions, dSender, meta.ledger_writer_role, dOrder));
  const policyD = observation.policy_logs.some((log) => log.topics[0] === TOPICS.policyRegistered
    && log.topics[1]?.toLowerCase() === meta.policy_hash.toLowerCase() && compareOrder(orderOfLog(log), dOrder) < 0);
  const approvalRecorded = observation.approval_logs.some((log) => log.topics[0] === TOPICS.approval
    && log.topics[1]?.toLowerCase() === hashes.action_hash.toLowerCase()
    && log.topics[2]?.toLowerCase() === hashes.approval_hash.toLowerCase()
    && addressFromTopic(log.topics[3]!) === meta.approval_actor.toLowerCase()
    && dataWord(log.data, 1) === hashes.artifact_hash.toLowerCase()
    && Number.parseInt(dataWord(log.data, 4), 16) === 0 // all controlled approvals are non-expiring
    && compareOrder(orderOfLog(log), dOrder) < 0);
  const approvalRevoked = observation.approval_logs.some((log) => log.topics[0] === TOPICS.approvalRevoked
    && log.topics[1]?.toLowerCase() === hashes.approval_hash.toLowerCase() && compareOrder(orderOfLog(log), dOrder) < 0);
  const approvalD = approvalRecorded && !approvalRevoked && actorActiveAt(observation.actor_logs, meta.approval_actor, dOrder);
  const writeN = anchorReceipt.status === "0x1" ? "accepted" : "reverted";
  const writeD = deploymentReceipt.status === "0x1" ? "accepted" : "reverted";
  const failure = writeN === "reverted" || !authorityN ? "N" : writeD === "reverted" || !authorityD || !policyD || !approvalD ? "D" : null;
  return {
    write_N: writeN,
    write_D: writeD,
    verdict: writeD === "reverted" ? "NOT_APPLICABLE" : failure === null ? "PASS" : "FAIL",
    failure_boundary: failure,
    authority_at_N: authorityN,
    authority_at_D: authorityD,
    policy_at_D: policyD,
    approval_at_D: approvalD,
    N_order: nOrder,
    D_order: dOrder,
    N_sender: anchorReceipt.from,
    D_sender: deploymentReceipt.from,
    D_revert_reason: null,
    D_source_level_cause: writeD === "reverted" ? "DeploymentRegistry._requireDeploymentWriter: sender lacks DEPLOYER_ROLE and LEDGER_WRITER_ROLE" : null,
  };
}
