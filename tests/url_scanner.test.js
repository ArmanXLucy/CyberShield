import test from 'node:test'
import assert from 'node:assert/strict'
import { _test, scanUrl } from '../url_scanner.js'

test('accepts common URL forms and normalizes missing scheme', () => {
  assert.equal(_test.normalizeUrl('example.com').protocol, 'https:')
  assert.equal(_test.normalizeUrl('www.example.com').hostname, 'www.example.com')
  assert.equal(
    _test.normalizeUrl('https://example.com:8443/a?b=c').port,
    '8443'
  )
})

test('rejects unsupported schemes and embedded credentials', () => {
  assert.throws(
    () => _test.normalizeUrl('ftp://example.com'),
    /Only HTTP and HTTPS/
  )

  assert.throws(
    () => _test.normalizeUrl('https://user:pass@example.com'),
    /embedded usernames or passwords/
  )
})

test('blocks private and SSRF-style numeric destinations', () => {
  assert.throws(
    () => _test.normalizeUrl('http://localhost'),
    /Private or local/
  )

  assert.throws(
    () => _test.normalizeUrl('http://127.0.0.1'),
    /Private or local/
  )

  assert.throws(
    () => _test.normalizeUrl('http://169.254.169.254'),
    /Private or local/
  )

  assert.throws(
    () => _test.normalizeUrl('http://2130706433'),
    /Private or local/
  )

  assert.throws(
    () => _test.normalizeUrl('http://0x7f000001'),
    /Private or local/
  )
})

test('extracts registered domains at the ownership boundary', () => {
  assert.equal(
    _test.registeredDomain('login.accounts.example.com'),
    'example.com'
  )

  assert.equal(
    _test.registeredDomain('login.example.co.uk'),
    'example.co.uk'
  )
})

test('structural analysis reports signals without declaring maliciousness', () => {
  const url = _test.normalizeUrl(
    'https://login.account.security.example.com:8080/verify?redirect=https%3A%2F%2Fexample.com&token=secret'
  )

  const analysis = _test.structuralAnalysis(url)

  assert.equal(analysis.registered_domain, 'example.com')
  assert.equal(analysis.flags.suspicious_port, true)
  assert.equal(analysis.flags.redirect_parameters, true)
  assert.equal(analysis.flags.suspicious_keywords, true)
})

test('sensitive query values are redacted from display output', () => {
  const safe = _test.safeUrlForDisplay(
    'https://example.com/reset?token=abc123&email=user@example.com&next=%2Fhome'
  )

  assert.match(safe, /token=REDACTED/)
  assert.match(safe, /email=REDACTED/)
  assert.doesNotMatch(safe, /abc123/)
})

test('risk engine only produces malicious for authoritative reputation evidence', () => {
  const result = _test.riskEngine(
    [
      {
        severity: 'low',
        category: 'url_structure',
        title: 'Long URL'
      }
    ],
    [
      {
        status: 'completed'
      }
    ]
  )

  assert.notEqual(result.label, 'MALICIOUS')

  const malicious = _test.riskEngine(
    [
      {
        severity: 'critical',
        category: 'reputation',
        title: 'Known malicious indicator matched'
      }
    ],
    [
      {
        status: 'completed'
      }
    ]
  )

  assert.equal(malicious.label, 'MALICIOUS')
})

test('mock mode performs a complete deterministic scan without external threat API calls', async () => {
  const previous = process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS

  process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS = 'true'

  try {
    const report = await scanUrl('https://example.com')

    assert.equal(report.scan_type, 'url')
    assert.ok(report.overall)
    assert.ok(Array.isArray(report.providers))
    assert.ok(report.coverage.total_checks >= 4)
    assert.ok(!report.scanned_url.includes('undefined'))
  } finally {
    if (previous === undefined) {
      delete process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS
    } else {
      process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS = previous
    }
  }
})