export const providerStatuses = {
  FOUND: 'found',
  NOT_FOUND: 'not_found',
  UNAVAILABLE: 'unavailable',
  ERROR: 'error',
}

export function providerResult(base) {
  return {
    provider: base.provider,
    source_display_name: base.source_display_name || base.provider,
    status: base.status || providerStatuses.UNAVAILABLE,
    reason: base.reason || null,
    findings: Array.isArray(base.findings) ? base.findings : [],
    checked_at: new Date().toISOString(),
  }
}

