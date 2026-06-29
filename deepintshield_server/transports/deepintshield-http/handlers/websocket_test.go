package handlers

import (
	"context"
	"testing"

	"github.com/fasthttp/websocket"
)

func TestShouldReceiveTenantBroadcast(t *testing.T) {
	tests := []struct {
		name          string
		clientTenant  string
		messageTenant string
		want          bool
	}{
		{name: "matching tenant", clientTenant: "tenant-a", messageTenant: "tenant-a", want: true},
		{name: "different tenant", clientTenant: "tenant-a", messageTenant: "tenant-b", want: false},
		{name: "global only matches global", clientTenant: "", messageTenant: "", want: true},
		{name: "tenant client does not receive global-scoped tenantless payload", clientTenant: "tenant-a", messageTenant: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldReceiveTenantBroadcast(tt.clientTenant, tt.messageTenant); got != tt.want {
				t.Fatalf("shouldReceiveTenantBroadcast(%q, %q) = %v, want %v", tt.clientTenant, tt.messageTenant, got, tt.want)
			}
		})
	}
}

func TestSnapshotClientsForTenant(t *testing.T) {
	handler := NewWebSocketHandler(context.Background(), nil)
	clientA := &WebSocketClient{conn: &websocket.Conn{}, tenantID: "tenant-a"}
	clientB := &WebSocketClient{conn: &websocket.Conn{}, tenantID: "tenant-b"}
	clientGlobal := &WebSocketClient{conn: &websocket.Conn{}, tenantID: ""}

	handler.clients[clientA.conn] = clientA
	handler.clients[clientB.conn] = clientB
	handler.clients[clientGlobal.conn] = clientGlobal

	tenantAClients := handler.snapshotClientsForTenant("tenant-a")
	if len(tenantAClients) != 1 || tenantAClients[0] != clientA {
		t.Fatalf("expected only tenant-a client, got %+v", tenantAClients)
	}

	globalClients := handler.snapshotClientsForTenant("")
	if len(globalClients) != 1 || globalClients[0] != clientGlobal {
		t.Fatalf("expected only global client, got %+v", globalClients)
	}
}
