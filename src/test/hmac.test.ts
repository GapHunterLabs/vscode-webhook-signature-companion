import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { computeHmac, stripKnownPrefix, verifySignature } from '../hmac';

test('computeHmac matches Node crypto directly (sanity check against the same primitive)', () => {
  const expected = createHmac('sha256', 'my-secret').update('hello', 'utf8').digest('hex');
  assert.equal(computeHmac('hello', 'my-secret', 'sha256', 'hex'), expected);
});

test('computeHmac produces different digests for sha1 vs sha256', () => {
  const sha1 = computeHmac('payload', 'secret', 'sha1', 'hex');
  const sha256 = computeHmac('payload', 'secret', 'sha256', 'hex');
  assert.notEqual(sha1, sha256);
});

test('computeHmac supports base64 encoding', () => {
  const hex = computeHmac('payload', 'secret', 'sha256', 'hex');
  const base64 = computeHmac('payload', 'secret', 'sha256', 'base64');
  assert.equal(Buffer.from(hex, 'hex').toString('base64'), base64);
});

test('stripKnownPrefix strips GitHub-style sha256= prefix', () => {
  assert.equal(stripKnownPrefix('sha256=abc123'), 'abc123');
});

test('stripKnownPrefix strips sha1= and sha512= too', () => {
  assert.equal(stripKnownPrefix('sha1=deadbeef'), 'deadbeef');
  assert.equal(stripKnownPrefix('sha512=cafef00d'), 'cafef00d');
});

test('stripKnownPrefix leaves a raw digest with no prefix untouched', () => {
  assert.equal(stripKnownPrefix('abc123'), 'abc123');
});

test('verifySignature reports a match for the correct signature', () => {
  const digest = computeHmac('{"a":1}', 'my-secret', 'sha256', 'hex');
  const result = verifySignature('{"a":1}', 'my-secret', 'sha256', 'hex', `sha256=${digest}`);
  assert.equal(result.matches, true);
  assert.equal(result.computed, digest);
});

test('verifySignature reports a mismatch for a wrong signature', () => {
  const result = verifySignature('{"a":1}', 'my-secret', 'sha256', 'hex', 'sha256=notarealsignature');
  assert.equal(result.matches, false);
});

test('verifySignature reports a mismatch when the secret is wrong', () => {
  const digest = computeHmac('{"a":1}', 'correct-secret', 'sha256', 'hex');
  const result = verifySignature('{"a":1}', 'wrong-secret', 'sha256', 'hex', `sha256=${digest}`);
  assert.equal(result.matches, false);
});

test('verifySignature is case-insensitive for hex encoding', () => {
  const digest = computeHmac('payload', 'secret', 'sha256', 'hex');
  const result = verifySignature('payload', 'secret', 'sha256', 'hex', digest.toUpperCase());
  assert.equal(result.matches, true);
});
