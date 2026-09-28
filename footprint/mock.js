export function mockProviderResult(provider, profile) {
  const id = profile.primary_username || 'mock-user'
  const base = {
    source_display_name: provider.displayName,
    provider: provider.name,
    status: 'not_found',
    reason: 'Mock provider returned no record.',
    findings: [],
  }

  if (provider.name === 'github') {
    base.status = 'found'
    base.reason = null
    base.findings = [{
      source: 'github',
      source_display_name: 'GitHub',
      status: 'found',
      match_type: 'confirmed',
      confidence: 'high',
      profile_url: `https://github.com/${encodeURIComponent(id)}`,
      matched_identifier: id,
      information: {
        username: id,
        display_name: profile.full_name || 'Mock User',
        bio: 'Deterministic mock profile for tests only.',
        location: 'Mock Location',
        website: profile.website || null,
        public_repositories: 3,
        public_email: null,
      },
      evidence: ['Mock mode is enabled; no external GitHub request was made.'],
      collected_at: new Date().toISOString(),
    }]
  }

  if (provider.name === 'hibp') {
    base.status = 'found'
    base.reason = null
    base.findings = [{
      source: 'hibp',
      source_display_name: 'Have I Been Pwned',
      status: 'found',
      match_type: 'confirmed',
      confidence: 'high',
      profile_url: 'https://haveibeenpwned.com/',
      matched_identifier: profile.email.replace(/^(.).*(?=@)/, '$1***'),
      breach_count: 1,
      breaches: [{
        name: 'CyberShieldMockBreach',
        title: 'CyberShield Mock Breach',
        domain: 'example.test',
        breach_date: '2025-01-01',
        added_date: '2025-01-10T00:00:00Z',
        modified_date: '2025-01-10T00:00:00Z',
        data_classes: ['Email addresses'],
        verified: true,
        unverified: false,
        sensitive: false,
      }],
      evidence: ['Mock mode is enabled; no external HIBP request was made.'],
      collected_at: new Date().toISOString(),
    }]
  }

  return base
}

