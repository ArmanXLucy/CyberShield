const clean = value => String(value || '').trim().toLowerCase()

function addSignal(map, value, field, source) {
  const normalized = clean(value)
  if (!normalized || normalized.length < 2) return
  if (!map.has(normalized)) map.set(normalized, { value, fields: new Set(), sources: new Set() })
  const item = map.get(normalized)
  item.fields.add(field)
  item.sources.add(source)
}

export function buildCorrelations(results) {
  const signals = new Map()

  for (const result of results) {
    const source = result.provider
    for (const finding of result.findings || []) {
      const info = finding.information || {}
      if (info.username) addSignal(signals, info.username, 'username', source)
      if (finding.matched_identifier && source !== 'hibp') addSignal(signals, finding.matched_identifier, 'identifier', source)
      if (info.display_name) addSignal(signals, info.display_name, 'display_name', source)
      if (info.website) addSignal(signals, info.website, 'website', source)
    }
  }

  const correlations = []
  for (const item of signals.values()) {
    if (item.sources.size < 2) continue

    const fields = [...item.fields]
    const sources = [...item.sources]
    const strong = fields.includes('website') || (fields.includes('username') && fields.includes('display_name'))

    correlations.push({
      source: 'correlation',
      source_display_name: 'CyberShield correlation',
      status: 'found',
      match_type: strong ? 'strong_match' : 'possible',
      confidence: strong ? 'high' : 'medium',
      profile_url: null,
      matched_identifier: null,
      information: {
        shared_signal: item.value,
        fields,
        sources,
      },
      evidence: [
        `The same public signal was returned by ${sources.join(' and ')}.`,
        'This is an evidence correlation only; identical usernames or public fields do not by themselves prove account ownership.',
      ],
      collected_at: new Date().toISOString(),
    })
  }

  return correlations.slice(0, 25)
}
