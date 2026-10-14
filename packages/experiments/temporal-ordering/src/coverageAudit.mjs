import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Multiset permutations filtered by constraints, independent of interleave/oracles.
export function plans(k = 1) {
  const result = [];
  for (let m = 0; m <= 2 * k + 1; m++) {
    const word = Array.from({ length: m }, (_, i) => i % 2 ? 'G' : 'R').join('');
    const bag = { S: 1, N: 1, D: 1, R: Math.ceil(m / 2), G: Math.floor(m / 2) };
    function visit(prefix) {
      if (prefix.length === m + 3) {
        if (prefix.filter(x => x === 'R' || x === 'G').join('') !== word) return;
        for (const sender of ['writer', 'actor']) for (const audit of [false, true])
          result.push({ ordered_events: ['A', ...prefix, ...(audit ? ['AUDIT'] : [])], deployment_transaction_sender: sender });
        return;
      }
      for (const x of Object.keys(bag)) {
        if (!bag[x] || (x === 'D' && !prefix.includes('N'))) continue;
        bag[x]--; visit([...prefix, x]); bag[x]++;
      }
    }
    visit([]);
  }
  return result;
}
export const key = p => `${p.deployment_transaction_sender}|${p.ordered_events.join(',')}`;
export function partition(p) {
  const held = boundary => {
    const prior = p.ordered_events.slice(0, p.ordered_events.indexOf(boundary)).filter(x => x === 'R' || x === 'G');
    return !prior.length || prior.at(-1) === 'G';
  };
  const n = held('N'), actorD = held('D'), d = p.deployment_transaction_sender === 'writer' || actorD;
  return { n, d, raw: `${p.deployment_transaction_sender}/${+n}/${+actorD}`, semantic: `${p.deployment_transaction_sender}/${+n}/${+d}` };
}
export function compare(expected, actual) {
  const a = new Set(expected.map(key)), b = new Set(actual.map(key));
  return { expected: expected.length, actual: actual.length, duplicates: actual.length - b.size,
    missing: [...a].filter(x => !b.has(x)), extra: [...b].filter(x => !a.has(x)) };
}
export function audit(workspace) {
  const hashes = {};
  const read = path => { const bytes = readFileSync(join(workspace, path)); hashes[path] = createHash('sha256').update(bytes).digest('hex'); return bytes.toString(); };
  const json = path => JSON.parse(read(path));
  const manifest = json('git/context/ciss2027/ordering_enumeration/enumeration_run_manifest.json');
  for (const item of manifest.artifact_hashes) if (createHash('sha256').update(readFileSync(join(workspace, item.path))).digest('hex') !== item.sha256) throw Error(`Hash mismatch: ${item.path}`);
  for (const item of manifest.artifact_hashes) hashes[item.path] = item.sha256;
  const root = 'git/software/packages/experiments/temporal-ordering/';
  const cases = json(root + 'cases.enumerated.k1.json').cases;
  const named = json(root + 'cases.json').cases, mapping = json(root + 'named_mapping.k1.json');
  const tsv = read(root + 'cases.enumerated.k1.tsv').trim().split(/\r?\n/);
  if (tsv.some((line, i) => line !== `${cases[i].case_id}|${cases[i].deployment_transaction_sender}|${cases[i].ordered_events.join(' ')}`) || tsv.length !== cases.length) throw Error('TSV mismatch');
  for (const p of named) if (key(cases.find(c => c.case_id === mapping[p.case_id])) !== key(p)) throw Error('Named mapping mismatch');
  const run = id => `git/software/runs/${id}/temporal_ordering/`;
  const bRoot = run(manifest.baseline_run_id), hRoot = run(manifest.hardened_run_id);
  for (const r of [bRoot, hRoot]) if (JSON.stringify(json(r + 'cases.json').cases) !== JSON.stringify(cases)) throw Error('Run plans differ');
  const base = json(bRoot + 'temporal_ordering_results.json').rows;
  const hard = json(hRoot + 'hardened_run_results.json').rows;
  const segl = json(bRoot + 'temporal_ordering_segl_events.json').cases;
  const hardSegl = json(hRoot + 'hardened_segl_events.json').cases;
  const indexed = rows => { const m = new Map(rows.map(x => [x.case_id, x])); if (m.size !== cases.length || rows.length !== cases.length || cases.some(p => !m.has(p.case_id))) throw Error('Observation IDs incomplete/duplicate'); return m; };
  const b = indexed(base), h = indexed(hard), s = indexed(segl), hs = indexed(hardSegl);
  const br = json(bRoot + 'temporal_ordering_besu_receipts.json').receipts;
  const hr = json(hRoot + 'hardened_besu_receipts.json').receipts;
  const receipt = (rows, id, step) => { const found = rows.filter(x => x.case_id === id && x.step === step); if (found.length > 1) throw Error('Duplicate boundary receipt'); return found[0]?.receipt; };
  const raw = {}, classes = {}, failures = [];
  for (const p of cases) {
    const q = partition(p), a = b.get(p.case_id), z = h.get(p.case_id);
    raw[q.raw] = (raw[q.raw] || 0) + 1;
    const signature = [a.besu_N_write, a.besu_D_write, a.besu_replay, z.N_write, z.D_write, z.besu_replay, a.segl_replay].join('/');
    const c = classes[q.semantic] ||= { count: 0, outcomes: {} }; c.count++; c.outcomes[signature] = (c.outcomes[signature] || 0) + 1;
    if (a.authority_N !== q.n || a.authority_D !== q.d || z.authority_at_N !== q.n) failures.push(`${p.case_id}: authority`);
    const expectedBase = ['accepted', q.d ? 'accepted' : 'reverted', q.d ? (q.n ? 'PASS' : 'FAIL') : 'NOT_APPLICABLE'];
    const expectedHard = [q.n ? 'ACCEPT' : 'REVERT', !q.n ? 'NOT_ATTEMPTED' : q.d ? 'ACCEPT' : 'REVERT', q.n && q.d ? 'PASS' : 'NOT_APPLICABLE'];
    if ([a.besu_N_write, a.besu_D_write, a.besu_replay].join('/') !== expectedBase.join('/') || [z.N_write, z.D_write, z.besu_replay].join('/') !== expectedHard.join('/')) failures.push(`${p.case_id}: outcomes`);
    if ((q.d && a.besu_replay !== a.segl_replay) || (q.n && q.d && z.besu_replay !== z.segl_replay)) failures.push(`${p.case_id}: parity`);
    for (const stream of [s, hs]) { const v = stream.get(p.case_id).replay; if (v.authority_at_N !== q.n || v.authority_at_D !== q.d || v.verdict !== (q.n && q.d ? 'PASS' : 'FAIL') || v.integrity_issues.length) failures.push(`${p.case_id}: SEGL`); }
    for (const [rows, n, d] of [[br, a.besu_N_write === 'accepted', a.besu_D_write === 'accepted'], [hr, z.N_write === 'ACCEPT', z.D_write === 'ACCEPT']]) {
      const nr = receipt(rows, p.case_id, 'anchor_N'), dr = receipt(rows, p.case_id, 'deployment_D');
      if (!nr || (nr.status === '0x1') !== n || (dr ? (dr.status === '0x1') !== d : n)) failures.push(`${p.case_id}: receipts`);
    }
  }
  const count = fn => base.filter(fn).length;
  return { set: compare(plans(), cases), named: named.length, raw, classes, failures, hashes,
    totals: { invalidN: count(x => !x.authority_N), validN: count(x => x.authority_N), invalidNCommittedD: count(x => !x.authority_N && x.besu_D_write === 'accepted' && x.besu_replay === 'FAIL' && x.failure_boundary === 'N'), invalidNRevertedD: count(x => !x.authority_N && x.besu_D_write === 'reverted'), validFull: count(x => x.besu_replay === 'PASS'), validNRevertedD: count(x => x.authority_N && x.besu_D_write === 'reverted'), baselineComparable: count(x => x.besu_replay !== 'NOT_APPLICABLE'), hardenedComparable: hard.filter(x => x.besu_replay !== 'NOT_APPLICABLE').length },
    k2: { count: plans(2).length, classes: [...new Set(plans(2).map(p => partition(p).semantic))].sort() } };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = audit(resolve(process.argv[2]));
  result.hashes['coverageAudit.mjs'] = createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex');
  writeFileSync(process.argv[3], JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ ...result, hashes: undefined }, null, 2));
  if (result.failures.length || result.set.duplicates || result.set.missing.length || result.set.extra.length) process.exitCode = 1;
}
