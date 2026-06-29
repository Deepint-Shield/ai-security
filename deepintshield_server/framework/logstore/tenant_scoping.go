package logstore

import (
	"reflect"
	"strings"

	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	logstoreTenantCreateCallback = "deepintshield:logstore_assign_tenant"
	logstoreTenantQueryCallback  = "deepintshield:logstore_scope_tenant_query"
	logstoreTenantUpdateCallback = "deepintshield:logstore_scope_tenant_update"
	logstoreTenantDeleteCallback = "deepintshield:logstore_scope_tenant_delete"
)

func registerTenantCallbacks(db *gorm.DB) error {
	if err := db.Callback().Create().Before("gorm:create").Register(logstoreTenantCreateCallback, assignTenantOnCreate); err != nil {
		return err
	}
	if err := db.Callback().Query().Before("gorm:query").Register(logstoreTenantQueryCallback, scopeTenantStatement); err != nil {
		return err
	}
	if err := db.Callback().Update().Before("gorm:update").Register(logstoreTenantUpdateCallback, scopeTenantStatement); err != nil {
		return err
	}
	if err := db.Callback().Delete().Before("gorm:delete").Register(logstoreTenantDeleteCallback, scopeTenantStatement); err != nil {
		return err
	}
	return nil
}

func assignTenantOnCreate(tx *gorm.DB) {
	if tx == nil || tx.Statement == nil || tx.Statement.Schema == nil {
		return
	}
	if tx.Statement.Schema.LookUpField("TenantID") == nil {
		return
	}
	tenantID := tenantctx.TenantIDFromContext(tx.Statement.Context)
	if tenantID == "" {
		return
	}
	setTenantID(tx.Statement.ReflectValue, tenantID)
}

func setTenantID(value reflect.Value, tenantID string) {
	if !value.IsValid() {
		return
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Struct:
		field := value.FieldByName("TenantID")
		if field.IsValid() && field.CanSet() && field.Kind() == reflect.String && strings.TrimSpace(field.String()) == "" {
			field.SetString(tenantID)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			setTenantID(value.Index(i), tenantID)
		}
	}
}

func scopeTenantStatement(tx *gorm.DB) {
	if tx == nil || tx.Statement == nil || tx.Statement.Schema == nil {
		return
	}
	field := tx.Statement.Schema.LookUpField("TenantID")
	if field == nil {
		return
	}
	tenantID := tenantctx.TenantIDFromContext(tx.Statement.Context)
	if tenantID == "" {
		return
	}
	tx.Statement.AddClause(clause.Where{
		Exprs: []clause.Expression{
			clause.Eq{
				Column: clause.Column{Table: clause.CurrentTable, Name: field.DBName},
				Value:  tenantID,
			},
		},
	})
}
