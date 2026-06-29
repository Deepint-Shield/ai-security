/**
 * Test data factories for observability connector tests
 */

/**
 * Observability connector configuration
 */
export interface ObservabilityConnectorConfig {
  type: 'otel'
  enabled: boolean
  endpoint?: string
  apiKey?: string
}

/**
 * Create OTEL connector configuration data
 */
export function createOtelConnectorData(overrides: Partial<ObservabilityConnectorConfig> = {}): ObservabilityConnectorConfig {
  return {
    type: 'otel',
    enabled: true,
    endpoint: 'http://localhost:4318',
    ...overrides
  }
}
