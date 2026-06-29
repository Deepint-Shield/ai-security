package server

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	dynamicPlugins "github.com/deepint-shield/ai-security/framework/plugins"
	"github.com/deepint-shield/ai-security/framework/vectorstore"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/deepint-shield/ai-security/plugins/guardrails"
	"github.com/deepint-shield/ai-security/plugins/litellmcompat"
	"github.com/deepint-shield/ai-security/plugins/logging"
	"github.com/deepint-shield/ai-security/plugins/otel"
	"github.com/deepint-shield/ai-security/plugins/semanticcache"
	"github.com/deepint-shield/ai-security/plugins/telemetry"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/handlers"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
)

// InferPluginTypes determines which interface types a plugin implements
func InferPluginTypes(plugin schemas.BasePlugin) []schemas.PluginType {
	var types []schemas.PluginType
	if _, ok := plugin.(schemas.LLMPlugin); ok {
		types = append(types, schemas.PluginTypeLLM)
	}
	if _, ok := plugin.(schemas.MCPPlugin); ok {
		types = append(types, schemas.PluginTypeMCP)
	}
	if _, ok := plugin.(schemas.HTTPTransportPlugin); ok {
		types = append(types, schemas.PluginTypeHTTP)
	}
	return types
}

// Single-plugin methods used plugin create/update

// InstantiatePlugin creates a plugin instance but does NOT register it
// Registration is done separately via Config.RegisterPlugin()
func InstantiatePlugin(ctx context.Context, name string, path *string, pluginConfig any, deepintshieldConfig *lib.Config) (schemas.BasePlugin, error) {
	// Custom plugin (has path)
	if path != nil {
		return loadCustomPlugin(ctx, path, pluginConfig, deepintshieldConfig)
	}

	// Built-in plugin (by name)
	return loadBuiltinPlugin(ctx, name, pluginConfig, deepintshieldConfig)
}

// loadBuiltinPlugin instantiates a built-in plugin by name
func loadBuiltinPlugin(ctx context.Context, name string, pluginConfig any, deepintshieldConfig *lib.Config) (schemas.BasePlugin, error) {
	switch name {
	case telemetry.PluginName:
		telConfig := &telemetry.Config{
			CustomLabels: deepintshieldConfig.ClientConfig.PrometheusLabels,
		}
		// Merge push gateway config if provided (e.g., from config file or UI update)
		if pluginConfig != nil {
			extraConfig, err := MarshalPluginConfig[telemetry.Config](pluginConfig)
			if err == nil && extraConfig != nil && extraConfig.PushGateway != nil {
				telConfig.PushGateway = extraConfig.PushGateway
			}
		}
		return telemetry.Init(telConfig, deepintshieldConfig.ModelCatalog, logger)

	case logging.PluginName:
		loggingConfig, err := MarshalPluginConfig[logging.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal logging plugin config: %w", err)
		}
		return logging.Init(ctx, loggingConfig, logger, deepintshieldConfig.LogsStore,
			deepintshieldConfig.ModelCatalog, deepintshieldConfig.MCPCatalog)

	case governance.PluginName:
		governanceConfig, err := MarshalPluginConfig[governance.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal governance plugin config: %w", err)
		}
		inMemoryStore := &GovernanceInMemoryStore{Config: deepintshieldConfig}
		return governance.Init(ctx, governanceConfig, logger, deepintshieldConfig.ConfigStore,
			deepintshieldConfig.GovernanceConfig, deepintshieldConfig.ModelCatalog,
			deepintshieldConfig.MCPCatalog, inMemoryStore)

	case guardrails.PluginName:
		var guardrailsConfig *guardrails.Config
		var err error
		if pluginConfig != nil {
			guardrailsConfig, err = MarshalPluginConfig[guardrails.Config](pluginConfig)
			if err != nil {
				if err.Error() != "invalid config type" {
					return nil, fmt.Errorf("failed to marshal guardrails plugin config: %w", err)
				}
				logger.Warn("guardrails plugin config has invalid type; falling back to env/default runtime config")
				guardrailsConfig = nil
			}
		}
		evidenceStore, ok := deepintshieldConfig.LogsStore.(logstore.GuardrailEvidenceStore)
		if !ok {
			return nil, fmt.Errorf("guardrails plugin requires a guardrail evidence store")
		}
		return guardrails.Init(ctx, guardrailsConfig, logger, deepintshieldConfig.ConfigStore, evidenceStore)

	case otel.PluginName:
		otelConfig, err := MarshalPluginConfig[otel.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal otel plugin config: %w", err)
		}
		return otel.Init(ctx, otelConfig, logger, deepintshieldConfig.ModelCatalog, handlers.GetVersion())

	case litellmcompat.PluginName:
		litellmConfig, err := MarshalPluginConfig[litellmcompat.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal litellmcompat plugin config: %w", err)
		}
		return litellmcompat.Init(*litellmConfig, logger)

	case semanticcache.PluginName:
		semanticConfig, err := MarshalPluginConfig[semanticcache.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal semantic cache plugin config: %w", err)
		}
		// Basic OSS cache: exact-match + embedding-similarity response caching
		// with TTL and scoping. No entitlement gate. Embeddings are produced by
		// calling an embedding provider through the gateway core (lib.NewBaseAccount).
		//
		// Direct/semantic caching need a vector store; prompt caching and
		// hallucination control don't. When the store is unavailable, hand the
		// plugin a no-op store so those still run and lookups just miss, rather
		// than failing the whole plugin (and losing hallucination control with it).
		cacheStore := deepintshieldConfig.VectorStore
		if cacheStore == nil {
			cacheStore = vectorstore.NewNoopStore()
		}
		return semanticcache.Init(ctx, semanticConfig, logger, cacheStore, lib.NewBaseAccount(deepintshieldConfig))

	default:
		return nil, fmt.Errorf("unknown built-in plugin: %s", name)
	}
}

// loadCustomPlugin loads a plugin from a shared object file
func loadCustomPlugin(ctx context.Context, path *string, pluginConfig any, deepintshieldConfig *lib.Config) (schemas.BasePlugin, error) {
	logger.Info("loading custom plugin from path %s", *path)

	plugin, err := deepintshieldConfig.PluginLoader.LoadPlugin(*path, pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom plugin: %w", err)
	}
	return plugin, nil
}

// LoadPlugins loads the plugins for the server.
func (s *DeepIntShieldHTTPServer) LoadPlugins(ctx context.Context) error {
	// Load built-in plugins first (order matters)
	if err := s.loadBuiltinPlugins(ctx); err != nil {
		return err
	}
	// Load custom plugins from config
	if err := s.loadCustomPlugins(ctx); err != nil {
		return err
	}
	// Sort all plugins by placement group and order
	s.Config.SortAndRebuildPlugins()
	return nil
}

// getPluginConfig retrieves a plugin's config from PluginConfigs by name.
// With per-workspace bootstrap PluginConfigs may contain multiple rows per
// name (one per workspace_id + an optional global); this returns the first
// match, which callers should treat as "the global default for this name".
// Callers that need every workspace's instance should use getPluginConfigsByName.
func (s *DeepIntShieldHTTPServer) getPluginConfig(name string) *schemas.PluginConfig {
	for _, cfg := range s.Config.PluginConfigs {
		if cfg.Name == name {
			return cfg
		}
	}
	return nil
}

// workspaceIDFromConfig returns the workspace tag from a PluginConfig, or ""
// for a global (untagged) config. Centralized so the per-workspace bootstrap
// loop and any future caller don't have to repeat the nil-pointer dance.
func workspaceIDFromConfig(cfg *schemas.PluginConfig) string {
	if cfg == nil || cfg.WorkspaceID == nil {
		return ""
	}
	return *cfg.WorkspaceID
}

// getPluginConfigsByName returns every PluginConfig with the given name -
// one per workspace_id plus any global (WorkspaceID == nil) entry. Used by
// the per-workspace bootstrap for plugins (currently semantic_cache) that
// need a separate runtime instance per workspace.
func (s *DeepIntShieldHTTPServer) getPluginConfigsByName(name string) []*schemas.PluginConfig {
	var out []*schemas.PluginConfig
	for _, cfg := range s.Config.PluginConfigs {
		if cfg.Name == name {
			out = append(out, cfg)
		}
	}
	return out
}

// loadBuiltinPlugins loads required built-in plugins in specific order
func (s *DeepIntShieldHTTPServer) loadBuiltinPlugins(ctx context.Context) error {
	builtinPlacement := schemas.Ptr(schemas.PluginPlacementBuiltin)

	// 1. Telemetry (always first - tracks everything)
	if err := s.registerPluginWithStatus(ctx, telemetry.PluginName, nil, nil, true); err != nil {
		return err
	}
	s.Config.SetPluginOrderInfo(telemetry.PluginName, builtinPlacement, schemas.Ptr(1))

	// 2. Logging (if enabled)
	if s.Config.ClientConfig.EnableLogging && s.Config.LogsStore != nil {
		config := &logging.Config{
			DisableContentLogging: &s.Config.ClientConfig.DisableContentLogging,
			LoggingHeaders:        &s.Config.ClientConfig.LoggingHeaders,
		}
		s.registerPluginWithStatus(ctx, logging.PluginName, nil, config, false)
	} else {
		s.markPluginDisabled(logging.PluginName)
	}
	s.Config.SetPluginOrderInfo(logging.PluginName, builtinPlacement, schemas.Ptr(2))

	// 3. Governance (if enabled and not enterprise)
	if ctx.Value(schemas.DeepIntShieldContextKeyIsEnterprise) == nil {
		config := &governance.Config{
			IsVkMandatory:   &s.Config.ClientConfig.EnforceAuthOnInference,
			RequiredHeaders: &s.Config.ClientConfig.RequiredHeaders,
		}
		s.registerPluginWithStatus(ctx, governance.PluginName, nil, config, false)
	} else {
		s.markPluginDisabled(governance.PluginName)
	}
	s.Config.SetPluginOrderInfo(governance.PluginName, builtinPlacement, schemas.Ptr(3))

	// 4. Guardrails runtime enforcement (ON by default).
	//
	// The deterministic guardrail engine (PII + regex) must run on EVERY
	// inference path (chat, RAG, agent, MCP) out-of-the-box so the gateway
	// behaves the way the `deepintshield` SDK expects: PII is redacted/blocked
	// and the guardrail analytics populate without any operator setup. The
	// plugin runs the in-process embedded runtime engine when no external
	// guard URL/gRPC target is configured (guardrails.Init tolerates a nil
	// config and newGuardRuntime falls back to the embedded engine), so no
	// sidecar is needed for the default deterministic checks.
	//
	// Default ON: enabled unless an operator explicitly disabled the plugin
	// via a PluginConfig with Enabled=false. The env vars still force-enable
	// (and select an external runtime) when set.
	guardrailsConfig := s.getPluginConfig(guardrails.PluginName)
	guardrailsConfigured := guardrailsConfig == nil || guardrailsConfig.Enabled
	if !guardrailsConfigured {
		guardrailsConfigured = strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_URL")) != "" ||
			strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_GRPC_TARGET")) != ""
	}
	var guardrailsPlugin *guardrails.Plugin
	if guardrailsConfigured {
		if _, ok := s.Config.LogsStore.(logstore.GuardrailEvidenceStore); ok {
			var config any
			if guardrailsConfig != nil {
				config = guardrailsConfig.Config
			}
			guardrailsPluginConfig, err := MarshalPluginConfig[guardrails.Config](config)
			if err != nil && err.Error() != "invalid config type" {
				return fmt.Errorf("failed to marshal guardrails plugin config: %w", err)
			}
			if err != nil {
				logger.Warn("guardrails plugin config has invalid type; falling back to env/default runtime config")
				guardrailsPluginConfig = nil
			}
			evidenceStore := s.Config.LogsStore.(logstore.GuardrailEvidenceStore)
			plugin, err := guardrails.Init(ctx, guardrailsPluginConfig, logger, s.Config.ConfigStore, evidenceStore)
			if err != nil {
				logger.Error("failed to initialize %s plugin: %v", guardrails.PluginName, err)
				s.Config.UpdatePluginOverallStatus(guardrails.PluginName, guardrails.PluginName, schemas.PluginStatusError,
					[]string{fmt.Sprintf("error initializing %s plugin: %v", guardrails.PluginName, err)}, []schemas.PluginType{})
			} else {
				guardrailsPlugin = plugin
			}
		} else {
			s.markPluginDisabled(guardrails.PluginName)
		}
	} else {
		s.markPluginDisabled(guardrails.PluginName)
	}
	if guardrailsPlugin != nil {
		if err := s.registerInstantiatedPluginWithStatus(guardrails.PluginName, guardrailsPlugin, false); err != nil {
			return err
		}
	}
	s.Config.SetPluginOrderInfo(guardrails.PluginName, builtinPlacement, schemas.Ptr(5))

	// 7. OTEL (if configured in PluginConfigs)
	otelConfig := s.getPluginConfig(otel.PluginName)
	if otelConfig != nil && otelConfig.Enabled {
		s.registerPluginWithStatus(ctx, otel.PluginName, nil, otelConfig.Config, false)
	} else {
		s.markPluginDisabled(otel.PluginName)
	}
	s.Config.SetPluginOrderInfo(otel.PluginName, builtinPlacement, schemas.Ptr(7))

	// 8. Litellmcompat (if configured in PluginConfigs)
	litellmcompatConfig := s.getPluginConfig(litellmcompat.PluginName)
	if litellmcompatConfig != nil && litellmcompatConfig.Enabled {
		s.registerPluginWithStatus(ctx, litellmcompat.PluginName, nil, litellmcompatConfig.Config, false)
	} else {
		s.markPluginDisabled(litellmcompat.PluginName)
	}
	s.Config.SetPluginOrderInfo(litellmcompat.PluginName, builtinPlacement, schemas.Ptr(8))

	// 9. Semantic cache (basic OSS cache; if configured in PluginConfigs and a
	// vector store is available). No entitlement gate.
	semanticCacheConfig := s.getPluginConfig(semanticcache.PluginName)
	if semanticCacheConfig != nil && semanticCacheConfig.Enabled && s.Config.VectorStore != nil {
		s.registerPluginWithStatus(ctx, semanticcache.PluginName, nil, semanticCacheConfig.Config, false)
	} else {
		s.markPluginDisabled(semanticcache.PluginName)
	}
	s.Config.SetPluginOrderInfo(semanticcache.PluginName, builtinPlacement, schemas.Ptr(9))

	return nil
}

// loadCustomPlugins loads plugins from PluginConfigs
func (s *DeepIntShieldHTTPServer) loadCustomPlugins(ctx context.Context) error {
	for _, cfg := range s.Config.PluginConfigs {
		// Skip built-ins (already loaded)
		if lib.IsBuiltinPlugin(cfg.Name) {
			continue
		}
		// Handle disabled plugins
		if !cfg.Enabled {
			// For custom plugins with a path, verify to get the real plugin name
			if cfg.Path != nil {
				pluginName, err := s.Config.PluginLoader.VerifyBasePlugin(*cfg.Path)
				if err != nil {
					logger.Error("failed to verify disabled plugin %s: %v", cfg.Name, err)
					continue
				}
				// Store plugin status without instantiating (no Init() call, no resource usage)
				// Note: We can't determine types without instantiating, so pass empty slice
				s.Config.UpdatePluginOverallStatus(pluginName, cfg.Name, schemas.PluginStatusDisabled,
					[]string{fmt.Sprintf("plugin %s is disabled", cfg.Name)}, []schemas.PluginType{})
			} else {
				// Built-in plugin - use cfg.Name directly
				s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusDisabled,
					[]string{fmt.Sprintf("plugin %s is disabled", cfg.Name)}, []schemas.PluginType{})
			}
			continue
		}

		// Plugin is enabled - instantiate it
		plugin, err := InstantiatePlugin(ctx, cfg.Name, cfg.Path, cfg.Config, s.Config)
		if err != nil {
			// Skip enterprise plugins silently
			if slices.Contains(enterprisePlugins, cfg.Name) {
				continue
			}
			logger.Error("failed to load plugin %s: %v", cfg.Name, err)
			// Use cfg.Name since plugin may be nil when InstantiatePlugin returns an error
			s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusError,
				[]string{fmt.Sprintf("error loading plugin %s: %v", cfg.Name, err)}, []schemas.PluginType{})
			continue
		}

		// Ensure plugin is not nil before using it (defensive check)
		if plugin == nil {
			logger.Error("plugin %s instantiated but returned nil", cfg.Name)
			s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusError,
				[]string{fmt.Sprintf("plugin %s instantiated but returned nil", cfg.Name)}, []schemas.PluginType{})
			continue
		}

		// Tag with the workspace from the PluginConfig (empty for global /
		// config.json entries) so the pipeline routes per-workspace requests
		// to the right instance - see schemas.WorkspaceScoped.
		plugin = dynamicPlugins.WrapWithWorkspace(plugin, workspaceIDFromConfig(cfg))
		// Register enabled plugin and mark as active
		s.Config.ReloadPlugin(plugin)
		s.Config.SetPluginOrderInfo(plugin.GetName(), cfg.Placement, cfg.Order)
		s.Config.UpdatePluginOverallStatus(plugin.GetName(), cfg.Name, schemas.PluginStatusActive,
			[]string{fmt.Sprintf("plugin %s initialized successfully", cfg.Name)}, InferPluginTypes(plugin))
	}
	return nil
}

