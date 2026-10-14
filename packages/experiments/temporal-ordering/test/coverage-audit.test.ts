import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plans, partition, compare } from '../src/coverageAudit.mjs';

test('filtered multiset construction exhausts k1 and detects missing, extra and duplicate plans', () => {
  const p = plans();
  assert.equal(p.length, 420);
  assert.equal(new Set(p.map(x => partition(x).raw)).size, 8);
  assert.equal(new Set(p.map(x => partition(x).semantic)).size, 6);
  const broken = [...p.slice(1), p[1], { deployment_transaction_sender: 'actor', ordered_events: ['A', 'D', 'N', 'S'] }];
  const result = compare(p, broken);
  assert.equal(result.duplicates, 1); assert.equal(result.missing.length, 1); assert.equal(result.extra.length, 1);
});
test('administrator quotient ignores actor state at D; actor sender retains it', () => {
  const p = { deployment_transaction_sender: 'writer', ordered_events: ['A', 'S', 'N', 'R', 'D'] };
  assert.equal(partition(p).semantic, 'writer/1/1');
  assert.equal(partition({ ...p, deployment_transaction_sender: 'actor' }).semantic, 'actor/1/0');
  assert.equal(plans(2).length, 1512);
});
