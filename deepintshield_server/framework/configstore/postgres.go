package configstore

import (
	"context"
	"fmt"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
)

// PostgresConfig represents the configuration for a Postgres database.
type PostgresConfig struct {
	Host         *schemas.EnvVar `json:"host"`
	Port         *schemas.EnvVar `json:"port"`
	User         *schemas.EnvVar `json:"user"`
	Password     *schemas.EnvVar `json:"password"`
	DBName       *schemas.EnvVar `json:"db_name"`
	SSLMode      *schemas.EnvVar `json:"ssl_mode"`
	MaxIdleConns int             `json:"max_idle_conns"`
	MaxOpenConns int             `json:"max_open_conns"`
	// ReadReplicas is an optional list of read-only DSNs that GORM
	// routes SELECT-only queries to. Writes always go to the primary
	// configured above. Each entry is a full Postgres DSN; the
	// connection pool config (MaxOpenConns, MaxIdleConns,
	// ConnMaxLifetime) is inherited from the primary.
	//
	// Use this for horizontal read scale: dashboard list queries,
	// log histograms, audit-log searches all become eligible to run
	// against replicas, freeing the primary for writes + the
	// inference auth path.
	ReadReplicas []string `json:"read_replicas,omitempty"`
}

// newPostgresConfigStore creates a new Postgres config store.
func newPostgresConfigStore(ctx context.Context, config *PostgresConfig, logger schemas.Logger) (ConfigStore, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	// Validate required config
	if config.Host == nil || config.Host.GetValue() == "" {
		return nil, fmt.Errorf("postgres host is required")
	}
	if config.Port == nil || config.Port.GetValue() == "" {
		return nil, fmt.Errorf("postgres port is required")
	}
	if config.User == nil || config.User.GetValue() == "" {
		return nil, fmt.Errorf("postgres user is required")
	}
	if config.Password == nil {
		return nil, fmt.Errorf("postgres password is required")
	}
	if config.DBName == nil || config.DBName.GetValue() == "" {
		return nil, fmt.Errorf("postgres db name is required")
	}
	if config.SSLMode == nil || config.SSLMode.GetValue() == "" {
		return nil, fmt.Errorf("postgres ssl mode is required")
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", config.Host.GetValue(), config.Port.GetValue(), config.User.GetValue(), config.Password.GetValue(), config.DBName.GetValue(), config.SSLMode.GetValue())
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
	}), &gorm.Config{
		Logger: newGormLogger(logger),
	})
	if err != nil {
		return nil, err
	}

	// Configure connection pool. Defaults sized for a multi-tenant
	// gateway running ~10-100 concurrent requests per replica:
	//   - MaxOpenConns 200: caps at 200 in-flight queries per pod.
	//     With 5 replicas that's 1000 against the primary - well under
	//     a typical PG max_connections of 200-500 only because PG sees
	//     5 separate clients. Set lower if you have many replicas.
	//   - MaxIdleConns 50: reuses warm connections for the steady state
	//     without holding the entire pool open during quiet periods.
	//   - ConnMaxLifetime 5m: forces refresh so PgBouncer / Cloud SQL
	//     proxies can rebalance and stale TCP gets pruned.
	//   - ConnMaxIdleTime 90s: releases idle connections back to the
	//     pool aggressively so we don't sit on capacity we're not
	//     using - critical when many replicas share a connection
	//     budget.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	maxIdleConns := config.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 50
	}
	sqlDB.SetMaxIdleConns(maxIdleConns)

	maxOpenConns := config.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = 200
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)

	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(90 * time.Second)

	// Optional read-replica routing. When ReadReplicas is non-empty
	// GORM ships SELECT statements to the replicas (round-robin) and
	// keeps every other statement on the primary. Transactions and
	// any explicit `db.Clauses(dbresolver.Write).Find(...)` stay on
	// the primary. The pool sizes above apply per replica connection.
	if len(config.ReadReplicas) > 0 {
		replicaDialectors := make([]gorm.Dialector, 0, len(config.ReadReplicas))
		for _, replicaDSN := range config.ReadReplicas {
			if replicaDSN == "" {
				continue
			}
			replicaDialectors = append(replicaDialectors, postgres.New(postgres.Config{DSN: replicaDSN}))
		}
		if len(replicaDialectors) > 0 {
			resolver := dbresolver.Register(dbresolver.Config{
				Replicas:          replicaDialectors,
				Policy:            dbresolver.RandomPolicy{},
				TraceResolverMode: false,
			}).
				SetMaxIdleConns(maxIdleConns).
				SetMaxOpenConns(maxOpenConns).
				SetConnMaxLifetime(5 * time.Minute).
				SetConnMaxIdleTime(90 * time.Second)
			if err := db.Use(resolver); err != nil {
				return nil, fmt.Errorf("failed to register read-replica resolver: %w", err)
			}
		}
	}

	d := &RDBConfigStore{db: db, logger: logger}
	if err := registerTenantCallbacks(db); err != nil {
		return nil, fmt.Errorf("failed to register tenant callbacks: %w", err)
	}
	// Run migrations
	if err := triggerMigrations(ctx, db); err != nil {
		// Closing the DB connection
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			if closeErr := sqlDB.Close(); closeErr != nil {
				logger.Error("failed to close DB connection: %v", closeErr)
			}
		}
		return nil, err
	}
	// Encrypt any plaintext rows if encryption is enabled
	if err := d.EncryptPlaintextRows(ctx); err != nil {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			if closeErr := sqlDB.Close(); closeErr != nil {
				logger.Error("failed to close DB connection: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to encrypt plaintext rows: %w", err)
	}
	// Background worker that auto-rotates virtual keys whose schedule has
	// elapsed. Detached from the bootstrap context so it survives across
	// requests; the parent process exit / db.Close will tear it down.
	startVirtualKeyRotationWorker(context.Background(), db, d)
	return d, nil
}
