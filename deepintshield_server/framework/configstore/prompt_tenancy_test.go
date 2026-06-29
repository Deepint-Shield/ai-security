package configstore

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromptRepository_IsolatedByTenant(t *testing.T) {
	store := setupRDBTestStore(t)
	tenantA := withTenant(context.Background(), "tenant-a@example.com")
	tenantB := withTenant(context.Background(), "tenant-b@example.com")

	folderA := &tables.TableFolder{ID: "folder-a", Name: "Folder A"}
	folderB := &tables.TableFolder{ID: "folder-b", Name: "Folder B"}
	require.NoError(t, store.CreateFolder(tenantA, folderA))
	require.NoError(t, store.CreateFolder(tenantB, folderB))

	promptA := &tables.TablePrompt{ID: "prompt-a", Name: "Prompt A", FolderID: &folderA.ID}
	promptB := &tables.TablePrompt{ID: "prompt-b", Name: "Prompt B", FolderID: &folderB.ID}
	require.NoError(t, store.CreatePrompt(tenantA, promptA))
	require.NoError(t, store.CreatePrompt(tenantB, promptB))

	versionA := &tables.TablePromptVersion{
		PromptID:      promptA.ID,
		VersionNumber: 1,
		CommitMessage: "tenant-a version",
		IsLatest:      true,
	}
	versionB := &tables.TablePromptVersion{
		PromptID:      promptB.ID,
		VersionNumber: 1,
		CommitMessage: "tenant-b version",
		IsLatest:      true,
	}
	require.NoError(t, store.CreatePromptVersion(tenantA, versionA))
	require.NoError(t, store.CreatePromptVersion(tenantB, versionB))

	sessionA := &tables.TablePromptSession{PromptID: promptA.ID, Name: "Session A"}
	sessionB := &tables.TablePromptSession{PromptID: promptB.ID, Name: "Session B"}
	require.NoError(t, store.CreatePromptSession(tenantA, sessionA))
	require.NoError(t, store.CreatePromptSession(tenantB, sessionB))

	foldersA, err := store.GetFolders(tenantA)
	require.NoError(t, err)
	require.Len(t, foldersA, 1)
	assert.Equal(t, folderA.ID, foldersA[0].ID)

	foldersB, err := store.GetFolders(tenantB)
	require.NoError(t, err)
	require.Len(t, foldersB, 1)
	assert.Equal(t, folderB.ID, foldersB[0].ID)

	promptsA, err := store.GetPrompts(tenantA, nil)
	require.NoError(t, err)
	require.Len(t, promptsA, 1)
	assert.Equal(t, promptA.ID, promptsA[0].ID)

	promptsB, err := store.GetPrompts(tenantB, nil)
	require.NoError(t, err)
	require.Len(t, promptsB, 1)
	assert.Equal(t, promptB.ID, promptsB[0].ID)

	_, err = store.GetPromptByID(tenantA, promptB.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetPromptByID(tenantB, promptA.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	_, err = store.GetPromptVersionByID(tenantA, versionB.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetPromptVersionByID(tenantB, versionA.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	_, err = store.GetPromptSessionByID(tenantA, sessionB.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetPromptSessionByID(tenantB, sessionA.ID)
	assert.ErrorIs(t, err, ErrNotFound)
}
