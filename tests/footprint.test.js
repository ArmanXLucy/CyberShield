import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeProfile, maskEmail, maskPhone } from '../footprint/normalizer.js'
import { analyzeRisk } from '../footprint/risk_engine.js'

test('normalizes and de-duplicates footprint identifiers', () => {
  const profile = normalizeProfile({
    email: ' USER@example.com ',
    primary_username: 'codezero',
    aliases: 'codezero\nother\ncodezero',
    self_audit_confirmed: true,
  })
  assert.equal(profile.email, 'user@example.com')
  assert.deepEqual(profile.aliases, ['codezero', 'other'])
})

test('masks email and phone', () => {
  assert.equal(maskEmail('user@example.com'), 'u***@example.com')
  assert.equal(maskPhone('+91 9876541234'), '+91******1234')
})

test('risk engine distinguishes breach exposure', () => {
  const result = analyzeRisk([{
    provider: 'hibp',
    findings: [{
      source: 'hibp',
      information: {},
      breaches: [{ Name: 'Test' }],
      matched_identifier: 'u***@example.com',
    }],
  }])
  assert.equal(result.overall_risk, 'high')
  assert.equal(result.breach_count, 1)
  assert.equal(result.exposures.breach, 'exposed')
})

