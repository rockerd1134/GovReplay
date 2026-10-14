use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleValidationReport {
    pub bundle_name: String,
    pub bundle_hash: String,
    pub policy_count: usize,
    pub test_count: usize,
}

#[derive(Debug, Clone)]
pub struct LoadedPolicyBundle {
    pub bundle_name: String,
    pub bundle_hash: String,
    pub obligations: Value,
    pub schema: Schema,
    pub policies: PolicySet,
    pub tests: Vec<PolicyTestCase>,
    pub policy_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTestCase {
    pub file_name: String,
    pub name: String,
    pub expected_decision: PolicyDecision,
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub test_name: String,
    pub expected_decision: PolicyDecision,
    pub actual_decision: PolicyDecision,
    pub matched_expected: bool,
    pub policy_bundle_hash: String,
    pub policy_input_hash: String,
    pub obligation_ids: Vec<String>,
    pub resolved_obligations: Vec<Value>,
    pub obligations_hash: String,
    pub policy_decision_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

impl PolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

pub fn validate_bundle(bundle_dir: impl AsRef<Path>) -> Result<BundleValidationReport, String> {
    let bundle = load_policy_bundle(bundle_dir)?;

    Ok(BundleValidationReport {
        bundle_name: bundle.bundle_name,
        bundle_hash: bundle.bundle_hash,
        policy_count: bundle.policy_count,
        test_count: bundle.tests.len(),
    })
}

pub fn load_policy_bundle(bundle_dir: impl AsRef<Path>) -> Result<LoadedPolicyBundle, String> {
    let bundle_dir = bundle_dir.as_ref();
    let metadata = read_json(bundle_dir.join("metadata.json"))?;
    let policy_language = metadata
        .get("policy_language")
        .and_then(Value::as_str)
        .ok_or_else(|| "metadata.policy_language must be present".to_string())?;
    if policy_language != "cedar" {
        return Err(format!("metadata.policy_language must be cedar, got {policy_language}"));
    }

    let obligations = read_json(bundle_dir.join("obligations.yml"))?;
    let schema_source = read_text(bundle_dir.join("schema.cedarschema"))?;
    if schema_source.trim().is_empty() {
        return Err("schema.cedarschema must not be empty".to_string());
    }
    let (schema, warnings) = Schema::from_cedarschema_str(&schema_source)
        .map_err(|error| format!("Cedar schema parse failed: {error}"))?;
    let warning_count = warnings.count();
    if warning_count > 0 {
        return Err(format!("Cedar schema produced {warning_count} warning(s)"));
    }

    let policy_paths = sorted_files(bundle_dir.join("policies"), "cedar")?;
    if policy_paths.is_empty() {
        return Err("policies directory must contain at least one .cedar file".to_string());
    }

    let mut policy_source = String::new();
    for path in &policy_paths {
        policy_source.push_str(&read_text(path)?);
        policy_source.push('\n');
    }
    let policies: PolicySet = policy_source
        .parse()
        .map_err(|error| format!("Cedar policy parse failed: {error}"))?;

    let test_paths = sorted_files(bundle_dir.join("tests"), "json")?;
    if test_paths.is_empty() {
        return Err("tests directory must contain at least one .json file".to_string());
    }
    let tests = test_paths
        .iter()
        .map(|path| load_policy_test_case(path))
        .collect::<Result<Vec<_>, _>>()?;

    let bundle_name = bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy-bundle")
        .to_string();

    Ok(LoadedPolicyBundle {
        bundle_name,
        bundle_hash: compute_bundle_hash(bundle_dir)?,
        obligations,
        schema,
        policies,
        tests,
        policy_count: policy_paths.len(),
    })
}

pub fn evaluate_test_case(
    bundle: &LoadedPolicyBundle,
    test: &PolicyTestCase,
) -> Result<PolicyEvaluation, String> {
    let input = test
        .input
        .as_object()
        .ok_or_else(|| format!("{} input must be an object", test.file_name))?;
    let principal_input = input
        .get("principal")
        .ok_or_else(|| format!("{} input.principal is required", test.file_name))?;
    let action_input = input
        .get("action")
        .ok_or_else(|| format!("{} input.action is required", test.file_name))?;
    let resource_input = input
        .get("resource")
        .ok_or_else(|| format!("{} input.resource is required", test.file_name))?;
    let context_input = input
        .get("context")
        .ok_or_else(|| format!("{} input.context is required", test.file_name))?;

    let principal = entity_uid_from_fixture(principal_input, "principal")?;
    let action = action_uid_from_fixture(action_input)?;
    let resource = entity_uid_from_fixture(resource_input, "resource")?;
    let entities = entities_from_fixture(principal_input, resource_input, &bundle.schema)?;
    let context = Context::from_json_value(context_input.clone(), Some((&bundle.schema, &action)))
        .map_err(|error| format!("{} context does not conform to Cedar schema: {error}", test.file_name))?;
    let request = Request::new(principal, action, resource, context, Some(&bundle.schema))
        .map_err(|error| format!("{} request creation failed: {error}", test.file_name))?;
    let response = Authorizer::new().is_authorized(&request, &bundle.policies, &entities);
    let actual_decision = policy_decision_from_cedar(response.decision());
    let policy_input_hash = hash_json_value(&test.input)?;
    let resolved = resolve_obligations_for_input(bundle, &test.input)?;
    let policy_decision_hash = hash_json_value(&json!({
        "schema_version": "govprov.policy_evaluation.v1",
        "policy_bundle_hash": bundle.bundle_hash,
        "policy_input_hash": policy_input_hash,
        "decision": actual_decision.as_str(),
        "obligations_hash": resolved.obligations_hash,
    }))?;

    Ok(PolicyEvaluation {
        test_name: test.name.clone(),
        expected_decision: test.expected_decision,
        actual_decision,
        matched_expected: actual_decision == test.expected_decision,
        policy_bundle_hash: bundle.bundle_hash.clone(),
        policy_input_hash,
        obligation_ids: resolved.obligation_ids,
        resolved_obligations: resolved.records,
        obligations_hash: resolved.obligations_hash,
        policy_decision_hash,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedObligations {
    pub obligation_ids: Vec<String>,
    pub records: Vec<Value>,
    pub obligations_hash: String,
}

pub fn resolve_obligations_for_input(
    bundle: &LoadedPolicyBundle,
    input: &Value,
) -> Result<ResolvedObligations, String> {
    let input_object = input
        .as_object()
        .ok_or_else(|| "policy input must be an object".to_string())?;
    let action_id = input_object
        .get("action")
        .and_then(Value::as_object)
        .and_then(|action| action.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| "input.action.id must be a string".to_string())?;
    let resource_environment = input_object
        .get("resource")
        .and_then(Value::as_object)
        .and_then(|resource| resource.get("environment"))
        .and_then(Value::as_str)
        .ok_or_else(|| "input.resource.environment must be a string".to_string())?;

    let obligations_object = bundle
        .obligations
        .as_object()
        .ok_or_else(|| "obligations.yml must contain an object".to_string())?;
    let schema_version = required_string(
        obligations_object.get("schema_version"),
        "obligations.schema_version",
    )?;
    if schema_version != "govprov.obligations.v1" {
        return Err(format!(
            "obligations.schema_version must be govprov.obligations.v1, got {schema_version}"
        ));
    }
    let decision_ttl_seconds = obligations_object
        .get("defaults")
        .and_then(Value::as_object)
        .and_then(|defaults| defaults.get("decision_ttl_seconds"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "obligations.defaults.decision_ttl_seconds must be an integer".to_string())?;
    let obligations = obligations_object
        .get("obligations")
        .and_then(Value::as_array)
        .ok_or_else(|| "obligations.obligations must be an array".to_string())?;

    let mut records = Vec::new();
    for obligation in obligations {
        let obligation_object = obligation
            .as_object()
            .ok_or_else(|| "each obligation must be an object".to_string())?;
        let obligation_id =
            required_string(obligation_object.get("id"), "obligations[].id")?.to_string();
        let applies_to_actions = required_string_array(
            obligation_object.get("applies_to_actions"),
            &format!("obligation {obligation_id}.applies_to_actions"),
        )?;
        if !applies_to_actions.iter().any(|action| action == action_id) {
            continue;
        }

        records.push(json!({
            "schema_version": "govprov.resolved_obligation.v1",
            "id": obligation_id,
            "policy_bundle_hash": bundle.bundle_hash,
            "action_id": action_id,
            "resource_environment": resource_environment,
            "decision_ttl_seconds": decision_ttl_seconds,
            "categories": {
                "required_evidence": required_category(obligation_object, "required_evidence")?,
                "required_approval_roles": required_category(obligation_object, "required_approval_roles")?,
                "separation_of_duties": required_category(obligation_object, "separation_of_duties")?,
                "deployment_environment_constraints": required_category(obligation_object, "deployment_environment_constraints")?,
                "attestation_requirements": required_category(obligation_object, "attestation_requirements")?,
                "expiration": required_category(obligation_object, "expiration")?,
            }
        }));
    }
    records.sort_by(|left, right| {
        let left_id = left.get("id").and_then(Value::as_str).unwrap_or_default();
        let right_id = right.get("id").and_then(Value::as_str).unwrap_or_default();
        left_id.cmp(right_id)
    });
    let obligation_ids = records
        .iter()
        .map(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect::<Vec<_>>();
    let obligations_hash = hash_json_value(&Value::Array(records.clone()))?;

    Ok(ResolvedObligations {
        obligation_ids,
        records,
        obligations_hash,
    })
}

pub fn evaluate_bundle_tests(bundle_dir: impl AsRef<Path>) -> Result<Vec<PolicyEvaluation>, String> {
    let bundle = load_policy_bundle(bundle_dir)?;
    bundle
        .tests
        .iter()
        .map(|test| evaluate_test_case(&bundle, test))
        .collect()
}

pub fn fixture_bundle_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("bundles")
}

pub fn fixture_bundle_dirs() -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(fixture_bundle_root())
        .map_err(|error| format!("failed to read fixture bundles: {error}"))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("failed to read fixture bundle entry: {error}"))?
            .path();
        if path.is_dir() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub fn cedar_authorizer_smoke() -> Result<String, String> {
    let policy: PolicySet =
        r#"permit(principal == User::"alice", action == Action::"view", resource == File::"93");"#
            .parse()
            .map_err(|error| format!("Cedar smoke policy parse failed: {error}"))?;
    let action = r#"Action::"view""#
        .parse()
        .map_err(|error| format!("Cedar action parse failed: {error}"))?;
    let principal = r#"User::"alice""#
        .parse()
        .map_err(|error| format!("Cedar principal parse failed: {error}"))?;
    let resource = r#"File::"93""#
        .parse()
        .map_err(|error| format!("Cedar resource parse failed: {error}"))?;
    let request = Request::new(principal, action, resource, Context::empty(), None)
        .map_err(|error| format!("Cedar request creation failed: {error}"))?;
    let response = Authorizer::new().is_authorized(&request, &policy, &Entities::empty());

    Ok(format!("{:?}", response.decision()).to_ascii_lowercase())
}

pub fn default_fixture_bundle() -> PathBuf {
    fixture_bundle_root().join("software-delivery-p1-baseline")
}

fn read_text(path: impl AsRef<Path>) -> Result<String, String> {
    fs::read_to_string(path.as_ref())
        .map_err(|error| format!("failed to read {}: {error}", path.as_ref().display()))
}

fn read_json(path: impl AsRef<Path>) -> Result<Value, String> {
    let path = path.as_ref();
    serde_json::from_str(&read_text(path)?)
        .map_err(|error| format!("failed to parse JSON-compatible {}: {error}", path.display()))
}

fn load_policy_test_case(path: &Path) -> Result<PolicyTestCase, String> {
    let value = read_json(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy-test.json")
        .to_string();
    let object = value
        .as_object()
        .ok_or_else(|| format!("{file_name} must contain a JSON object"))?;
    let name = required_string(object.get("name"), &format!("{file_name}.name"))?.to_string();
    let expected_decision = match required_string(
        object.get("expected_decision"),
        &format!("{file_name}.expected_decision"),
    )? {
        "allow" => PolicyDecision::Allow,
        "deny" => PolicyDecision::Deny,
        other => return Err(format!("{file_name}.expected_decision must be allow or deny, got {other}")),
    };
    let input = object
        .get("input")
        .ok_or_else(|| format!("{file_name}.input is required"))?
        .clone();
    if !input.is_object() {
        return Err(format!("{file_name}.input must be an object"));
    }

    Ok(PolicyTestCase {
        file_name,
        name,
        expected_decision,
        input,
    })
}

fn entity_uid_from_fixture(value: &Value, label: &str) -> Result<EntityUid, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("input.{label} must be an object"))?;
    let entity_type = required_string(object.get("type"), &format!("input.{label}.type"))?;
    let entity_id = required_string(object.get("id"), &format!("input.{label}.id"))?;

    EntityUid::from_json(json!({
        "__entity": {
            "type": format!("GovProv::{entity_type}"),
            "id": entity_id
        }
    }))
    .map_err(|error| format!("input.{label} could not be mapped to Cedar entity uid: {error}"))
}

fn action_uid_from_fixture(value: &Value) -> Result<EntityUid, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "input.action must be an object".to_string())?;
    let action_type = required_string(object.get("type"), "input.action.type")?;
    if action_type != "GovernedAction" {
        return Err(format!("input.action.type must be GovernedAction, got {action_type}"));
    }
    let action_id = required_string(object.get("id"), "input.action.id")?;

    EntityUid::from_json(json!({
        "__entity": {
            "type": "GovProv::Action",
            "id": action_id
        }
    }))
    .map_err(|error| format!("input.action could not be mapped to Cedar action uid: {error}"))
}

fn entities_from_fixture(
    principal: &Value,
    resource: &Value,
    schema: &Schema,
) -> Result<Entities, String> {
    let principal_object = principal
        .as_object()
        .ok_or_else(|| "input.principal must be an object".to_string())?;
    let resource_object = resource
        .as_object()
        .ok_or_else(|| "input.resource must be an object".to_string())?;
    let principal_roles = principal_object
        .get("roles")
        .cloned()
        .ok_or_else(|| "input.principal.roles is required".to_string())?;
    let resource_environment = resource_object
        .get("environment")
        .cloned()
        .ok_or_else(|| "input.resource.environment is required".to_string())?;

    Entities::from_json_value(
        json!([
            {
                "uid": entity_uid_json(principal, "principal")?,
                "attrs": {
                    "roles": principal_roles
                },
                "parents": []
            },
            {
                "uid": entity_uid_json(resource, "resource")?,
                "attrs": {
                    "environment": resource_environment
                },
                "parents": []
            }
        ]),
        Some(schema),
    )
    .map_err(|error| format!("fixture entities do not conform to Cedar schema: {error}"))
}

fn entity_uid_json(value: &Value, label: &str) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("input.{label} must be an object"))?;
    let entity_type = required_string(object.get("type"), &format!("input.{label}.type"))?;
    let entity_id = required_string(object.get("id"), &format!("input.{label}.id"))?;

    Ok(json!({
        "type": format!("GovProv::{entity_type}"),
        "id": entity_id
    }))
}

fn required_string<'a>(value: Option<&'a Value>, path: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path} must be a string"))
}

fn required_string_array(value: Option<&Value>, path: &str) -> Result<Vec<String>, String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path} must be an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{path} entries must be strings"))
        })
        .collect()
}

fn required_category(
    obligation: &serde_json::Map<String, Value>,
    category: &str,
) -> Result<Value, String> {
    obligation
        .get(category)
        .cloned()
        .ok_or_else(|| format!("obligation {} is required", category))
}

fn policy_decision_from_cedar(decision: Decision) -> PolicyDecision {
    match decision {
        Decision::Allow => PolicyDecision::Allow,
        Decision::Deny => PolicyDecision::Deny,
    }
}

fn hash_json_value(value: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize JSON value for hashing: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(bytes);
    Ok(format!("0x{}", hex_lower(hash.finalize().as_slice())))
}

fn sorted_files(directory: impl AsRef<Path>, extension: &str) -> Result<Vec<PathBuf>, String> {
    let directory = directory.as_ref();
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("failed to read {}: {error}", directory.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("failed to read {} entry: {error}", directory.display()))?
            .path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some(extension) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn compute_bundle_hash(bundle_dir: &Path) -> Result<String, String> {
    let mut files = vec![
        PathBuf::from("metadata.json"),
        PathBuf::from("obligations.yml"),
        PathBuf::from("schema.cedarschema"),
    ];
    for child_dir in ["policies", "tests"] {
        for path in sorted_files(bundle_dir.join(child_dir), if child_dir == "policies" { "cedar" } else { "json" })? {
            let name = path
                .file_name()
                .ok_or_else(|| format!("{} has no file name", path.display()))?;
            files.push(PathBuf::from(child_dir).join(name));
        }
    }
    files.sort();

    let mut hash = Sha256::new();
    for relative_path in files {
        let relative = relative_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 bundle path: {}", relative_path.display()))?
            .replace('\\', "/");
        hash.update(relative.as_bytes());
        hash.update([0]);
        hash.update(
            fs::read(bundle_dir.join(&relative_path))
                .map_err(|error| format!("failed to read {}: {error}", relative_path.display()))?,
        );
        hash.update([0]);
    }
    Ok(format!("0x{}", hex_lower(hash.finalize().as_slice())))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cedar_dependency_authorizes_smoke_request() {
        assert_eq!(cedar_authorizer_smoke().unwrap(), "allow");
    }

    #[test]
    fn loads_p4_s4_p1_baseline_fixture_bundle() {
        let report = validate_bundle(default_fixture_bundle()).unwrap();

        assert_eq!(report.bundle_name, "software-delivery-p1-baseline");
        assert_eq!(report.policy_count, 1);
        assert_eq!(report.test_count, 2);
        assert!(report.bundle_hash.starts_with("0x"));
        assert_eq!(report.bundle_hash.len(), 66);
    }

    #[test]
    fn evaluates_all_fixture_policy_tests() {
        let mut evaluated = Vec::new();
        for bundle_dir in fixture_bundle_dirs().unwrap() {
            evaluated.extend(evaluate_bundle_tests(bundle_dir).unwrap());
        }

        assert_eq!(evaluated.len(), 12);
        for evaluation in evaluated {
            assert!(
                evaluation.matched_expected,
                "{} expected {} got {}",
                evaluation.test_name,
                evaluation.expected_decision.as_str(),
                evaluation.actual_decision.as_str(),
            );
            assert_eq!(evaluation.policy_bundle_hash.len(), 66);
            assert_eq!(evaluation.policy_input_hash.len(), 66);
            assert_eq!(evaluation.policy_decision_hash.len(), 66);
            assert_eq!(evaluation.obligations_hash.len(), 66);
            assert!(!evaluation.resolved_obligations.is_empty());
            for obligation in &evaluation.resolved_obligations {
                assert_eq!(
                    obligation.get("policy_bundle_hash").and_then(Value::as_str),
                    Some(evaluation.policy_bundle_hash.as_str())
                );
            }
        }
    }

    #[test]
    fn resolves_expected_obligations_for_allowed_fixture_cases() {
        let mut allowed = Vec::new();
        for bundle_dir in fixture_bundle_dirs().unwrap() {
            let bundle = load_policy_bundle(&bundle_dir).unwrap();
            for test in &bundle.tests {
                let evaluation = evaluate_test_case(&bundle, test).unwrap();
                if evaluation.actual_decision == PolicyDecision::Allow {
                    allowed.push((bundle.bundle_name.clone(), evaluation));
                }
            }
        }

        assert_eq!(allowed.len(), 6);
        let p1 = allowed
            .iter()
            .find(|(bundle_name, _)| bundle_name == "software-delivery-p1-baseline")
            .unwrap();
        assert_eq!(
            p1.1.obligation_ids,
            vec!["p1-runbook-baseline".to_string()]
        );
        let p2 = allowed
            .iter()
            .find(|(bundle_name, _)| bundle_name == "software-delivery-p2-strict-approval")
            .unwrap();
        assert_eq!(
            p2.1.obligation_ids,
            vec!["p2-config-dual-approval".to_string()]
        );
        let p3_runbook = allowed
            .iter()
            .find(|(bundle_name, evaluation)| {
                bundle_name == "software-delivery-p3-evidence-strengthened"
                    && evaluation
                        .obligation_ids
                        .contains(&"p3-runbook-strengthened-evidence".to_string())
            })
            .unwrap();
        assert_eq!(
            p3_runbook.1.obligation_ids,
            vec!["p3-runbook-strengthened-evidence".to_string()]
        );
        assert!(allowed.iter().any(|(_, evaluation)| evaluation
            .obligation_ids
            .contains(&"p3-patch-provenance".to_string())));
        assert!(allowed.iter().any(|(_, evaluation)| evaluation
            .obligation_ids
            .contains(&"p3-deployment-provenance".to_string())));
        assert!(allowed.iter().any(|(_, evaluation)| evaluation
            .obligation_ids
            .contains(&"p3-governance-admin-state-change".to_string())));
        for (_, evaluation) in allowed {
            let categories = evaluation.resolved_obligations[0]
                .get("categories")
                .and_then(Value::as_object)
                .unwrap();
            for category in [
                "required_evidence",
                "required_approval_roles",
                "separation_of_duties",
                "deployment_environment_constraints",
                "attestation_requirements",
                "expiration",
            ] {
                assert!(categories.contains_key(category), "missing {category}");
            }
        }
    }
}
