export function analyzeRisk(results) {
  const all = results.flatMap(r => r.findings || [])
  const recommendations = []
  const exposures = {
    email: 'none',
    username: 'none',
    name: 'none',
    bio: 'none',
    location: 'none',
    website: 'none',
    breach: 'none',
  }

  for (const finding of all) {
    const info = finding.information || {}
    if (info.public_email || info.email) exposures.email = 'exposed'
    if (finding.matched_identifier || info.username) exposures.username = 'exposed'
    if (info.display_name) exposures.name = 'exposed'
    if (info.bio || info.profile_description) exposures.bio = 'exposed'
    if (info.location) exposures.location = 'exposed'
    if (info.website || info.public_website) exposures.website = 'exposed'
    if (Array.isArray(finding.breaches) && finding.breaches.length) exposures.breach = 'exposed'
  }

  const breachCount = all.reduce((n, f) => n + (Array.isArray(f.breaches) ? f.breaches.length : 0), 0)
  if (breachCount) {
    recommendations.push('Change passwords for affected accounts and ensure unique passwords are used. Enable MFA where available.')
  }
  if (exposures.email === 'exposed') {
    recommendations.push('Consider using a dedicated public contact email instead of your primary personal email.')
  }
  if (exposures.location === 'exposed') {
    recommendations.push('Remove precise location information from public profiles if it is not necessary.')
  }
  const matchedSources = new Set(all.map(f => f.source))
  if (matchedSources.size >= 2 && exposures.username === 'exposed') {
    recommendations.push('Review whether username reuse across public profiles is intentional.')
  }
  if (matchedSources.has('github') && exposures.email === 'exposed') {
    recommendations.push('Review Git commit/email privacy settings and avoid exposing personal contact information in public repositories.')
  }

  let highest = 'low'
  if (breachCount || (exposures.email === 'exposed' && matchedSources.size >= 2)) highest = 'high'
  else if (exposures.location === 'exposed' || matchedSources.size >= 2) highest = 'medium'
  else if (!all.length) highest = 'informational'

  return {
    overall_risk: highest,
    breach_count: breachCount,
    exposures,
    recommendations: [...new Set(recommendations)].slice(0, 8),
  }
}

