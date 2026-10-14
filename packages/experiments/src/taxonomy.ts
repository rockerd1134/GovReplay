import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  ALL_FAULT_IDS,
  GOVERNANCE_DOMAINS,
  SYSTEM_CONFIGURATIONS,
  type FailureStage,
  type FaultId,
  type GovernanceDomain,
  type SystemConfiguration,
} from "./model.ts";

export const ARPE_PROPERTIES = [
  "evidence integrity",
  "historical policy-version binding",
  "approval authority and separation of duties",
  "artifact/deployment consistency",
  "anchor consistency",
  "ledger-backed governance-state replay",
] as const;

export type ArpeProperty = typeof ARPE_PROPERTIES[number] | "no injected fault control";

export type ArpeTestClass = {
  id: string;
  name: string;
  external_tradition: string;
  representative_sources: string[];
  arpe_property: ArpeProperty;
  fault_ids: FaultId[];
  governance_domain: GovernanceDomain;
  governance_domain_type: string;
  expected_domain: GovernanceDomain;
  cross_domain_dependency: GovernanceDomain[];
  expected_verification_stage: FailureStage;
  applies_to_configurations: SystemConfiguration[];
};

export type ArpeTaxonomy = {
  schema_version: "govprov.arpe_test_classes.v1";
  positioning_boundary: string;
  non_claims: string[];
  test_classes: ArpeTestClass[];
  by_fault_id: Map<FaultId, ArpeTestClass>;
};

const LEDGER_STATE_FAULTS = new Set<FaultId>(["F12", "H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"]);

let cachedTaxonomy: ArpeTaxonomy | null = null;

export function defaultTaxonomyPath(): string {
  return resolve(import.meta.dirname, "..", "..", "..", "experiments", "arpe_test_classes.yaml");
}

export function loadArpeTaxonomy(path = defaultTaxonomyPath()): ArpeTaxonomy {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const taxonomy = parseTaxonomy(parsed, path);
  validateTaxonomy(taxonomy, path);
  return taxonomy;
}

export function defaultArpeTaxonomy(): ArpeTaxonomy {
  cachedTaxonomy ??= loadArpeTaxonomy();
  return cachedTaxonomy;
}

export function metadataForFault(faultId: FaultId, taxonomy = defaultArpeTaxonomy()) {
  const testClass = taxonomy.by_fault_id.get(faultId);
  if (testClass === undefined) {
    throw new TypeError(`No ARPE test class maps fault ${faultId}`);
  }
  const ledgerStateRequirement = ledgerStateRequirementForFault(faultId);
  return {
    test_class_id: testClass.id,
    external_tradition: testClass.external_tradition,
    arpe_property: testClass.arpe_property,
    governance_domain: testClass.governance_domain,
    governance_domain_type: testClass.governance_domain_type,
    expected_domain: testClass.expected_domain,
    cross_domain_dependency: testClass.cross_domain_dependency,
    expected_stage: testClass.expected_verification_stage,
    requires_ledger_state: ledgerStateRequirement !== "no_ledger_state_required",
    ledger_state_requirement: ledgerStateRequirement,
  };
}

export function requiresLedgerState(faultId: FaultId): boolean {
  return LEDGER_STATE_FAULTS.has(faultId);
}

export function ledgerStateRequirementForFault(faultId: FaultId): string {
  if (faultId === "F12" || faultId === "H4") {
    return "ledger_anchor_readback";
  }
  if (faultId.startsWith("H")) {
    return "ledger_backed_governance_state";
  }
  return "no_ledger_state_required";
}

function parseTaxonomy(parsed: unknown, path: string): ArpeTaxonomy {
  if (!isRecord(parsed)) {
    throw new TypeError(`ARPE taxonomy must be an object: ${path}`);
  }
  const schemaVersion = stringField(parsed, "schema_version");
  if (schemaVersion !== "govprov.arpe_test_classes.v1") {
    throw new TypeError(`Unsupported ARPE taxonomy schema_version: ${schemaVersion}`);
  }
  const testClassesValue = parsed.test_classes;
  if (!Array.isArray(testClassesValue) || testClassesValue.length === 0) {
    throw new TypeError("ARPE taxonomy must include non-empty test_classes");
  }
  const testClasses = testClassesValue.map((item) => parseTestClass(item));
  return {
    schema_version: "govprov.arpe_test_classes.v1",
    positioning_boundary: stringField(parsed, "positioning_boundary"),
    non_claims: stringArray(parsed, "non_claims"),
    test_classes: testClasses,
    by_fault_id: new Map(),
  };
}

function parseTestClass(value: unknown): ArpeTestClass {
  if (!isRecord(value)) {
    throw new TypeError("Each ARPE test class must be an object");
  }
  return {
    id: stringField(value, "id"),
    name: stringField(value, "name"),
    external_tradition: stringField(value, "external_tradition"),
    representative_sources: stringArray(value, "representative_sources"),
    arpe_property: enumField(value, "arpe_property", [...ARPE_PROPERTIES, "no injected fault control"] as const),
    fault_ids: enumArray(value, "fault_ids", ALL_FAULT_IDS),
    governance_domain: enumField(value, "governance_domain", GOVERNANCE_DOMAINS),
    governance_domain_type: stringField(value, "governance_domain_type"),
    expected_domain: enumField(value, "expected_domain", GOVERNANCE_DOMAINS),
    cross_domain_dependency: optionalEnumArray(value, "cross_domain_dependency", GOVERNANCE_DOMAINS),
    expected_verification_stage: enumField(value, "expected_verification_stage", ["none", "evidence", "policy", "identity", "approval", "artifact", "deployment", "ledger", "contract_governance"] as const),
    applies_to_configurations: enumArray(value, "applies_to_configurations", SYSTEM_CONFIGURATIONS),
  };
}

function validateTaxonomy(taxonomy: ArpeTaxonomy, path: string): void {
  const seenClassIds = new Set<string>();
  const seenFaults = new Map<FaultId, string>();
  for (const testClass of taxonomy.test_classes) {
    if (seenClassIds.has(testClass.id)) {
      throw new TypeError(`Duplicate ARPE test class id ${testClass.id}`);
    }
    seenClassIds.add(testClass.id);
    for (const faultId of testClass.fault_ids) {
      const existing = seenFaults.get(faultId);
      if (existing !== undefined) {
        throw new TypeError(`Fault ${faultId} maps to both ${existing} and ${testClass.id}`);
      }
      seenFaults.set(faultId, testClass.id);
      taxonomy.by_fault_id.set(faultId, testClass);
    }
  }
  const missingFaults = ALL_FAULT_IDS.filter((faultId) => !seenFaults.has(faultId));
  if (missingFaults.length > 0) {
    throw new TypeError(`ARPE taxonomy ${path} does not map configured faults: ${missingFaults.join(", ")}`);
  }
  const coveredProperties = new Set(taxonomy.test_classes.map((testClass) => testClass.arpe_property));
  const missingProperties = ARPE_PROPERTIES.filter((property) => !coveredProperties.has(property));
  if (missingProperties.length > 0) {
    throw new TypeError(`ARPE taxonomy ${path} does not cover ARPE properties: ${missingProperties.join(", ")}`);
  }
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`Expected non-empty string field ${key}`);
  }
  return value;
}

function stringArray(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new TypeError(`${key} must be a non-empty string array`);
  }
  return value as string[];
}

function enumField<const T extends readonly string[]>(record: Record<string, unknown>, key: string, allowed: T): T[number] {
  const value = stringField(record, key);
  if (!allowed.includes(value)) {
    throw new TypeError(`${key} must be one of ${allowed.join(", ")}`);
  }
  return value;
}

function enumArray<const T extends readonly string[]>(record: Record<string, unknown>, key: string, allowed: T): T[number][] {
  const value = record[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${key} must be a non-empty array`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw new TypeError(`${key} contains unsupported value ${String(item)}`);
    }
    return item;
  });
}

function optionalEnumArray<const T extends readonly string[]>(record: Record<string, unknown>, key: string, allowed: T): T[number][] {
  const value = record[key];
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new TypeError(`${key} must be an array when present`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw new TypeError(`${key} contains unsupported value ${String(item)}`);
    }
    return item;
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
