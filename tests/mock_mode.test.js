import test from 'node:test'
import assert from 'node:assert/strict'

process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS = 'true'

const { createFootprintScan, runFootprintScan } = await import('../footprint/orchestrator.js')

test('mock footprint scan completes deterministically without external provider calls', async () => {
  const profile = createFootprintScan({
    email: 'user@example.com',
    primary_username: 'cybershield-test',
    full_name: 'Example User',
    aliases: ['alias1', 'alias1'],
    self_audit_confirmed: true,
  })

  const report = await runFootprintScan(profile)
  assert.equal(report.summary.checked_sources, 7)
  assert.ok(report.providers.some(item => item.provider === 'github' && item.status === 'found'))
  assert.ok(report.providers.some(item => item.provider === 'hibp' && item.status === 'found'))
  assert.equal(report.profile.email, 'u***@example.com')
  assert.equal(report.summary.breach_count, 1)
})
