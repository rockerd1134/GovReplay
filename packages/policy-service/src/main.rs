use govprov_policy_service::{
    default_fixture_bundle, evaluate_bundle_tests, fixture_bundle_dirs, load_policy_bundle,
};
use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let bundle_dirs = if args.first().and_then(|arg| arg.to_str()) == Some("--all-fixtures") {
        match fixture_bundle_dirs() {
            Ok(paths) => paths,
            Err(error) => exit_with_error(error),
        }
    } else {
        vec![args
            .first()
            .map(PathBuf::from)
            .unwrap_or_else(default_fixture_bundle)]
    };

    let mut total = 0usize;
    let mut failed = 0usize;
    for bundle_dir in bundle_dirs {
        let bundle = match load_policy_bundle(&bundle_dir) {
            Ok(bundle) => bundle,
            Err(error) => exit_with_error(error),
        };
        let evaluations = match evaluate_bundle_tests(&bundle_dir) {
            Ok(evaluations) => evaluations,
            Err(error) => exit_with_error(error),
        };

        println!("bundle_name={}", bundle.bundle_name);
        println!("bundle_hash={}", bundle.bundle_hash);
        println!("policy_count={}", bundle.policy_count);
        println!("test_count={}", evaluations.len());
        for evaluation in evaluations {
            total += 1;
            if !evaluation.matched_expected {
                failed += 1;
            }
            println!(
                "test={} expected={} actual={} matched={} input_hash={} obligations_hash={} decision_hash={} obligation_ids={} resolved_obligations={}",
                evaluation.test_name,
                evaluation.expected_decision.as_str(),
                evaluation.actual_decision.as_str(),
                evaluation.matched_expected,
                evaluation.policy_input_hash,
                evaluation.obligations_hash,
                evaluation.policy_decision_hash,
                serde_json::to_string(&evaluation.obligation_ids)
                    .unwrap_or_else(|_| "[]".to_string()),
                serde_json::to_string(&evaluation.resolved_obligations)
                    .unwrap_or_else(|_| "[]".to_string()),
            );
        }
    }

    println!("summary_total={total}");
    println!("summary_failed={failed}");
    if failed > 0 {
        process::exit(1);
    }
}

fn exit_with_error(error: String) -> ! {
    eprintln!("{error}");
    process::exit(1);
}
