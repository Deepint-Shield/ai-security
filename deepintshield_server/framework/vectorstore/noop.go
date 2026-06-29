package vectorstore

import "context"

// noopStore is the vector store the gateway falls back to when none is
// configured or the configured one can't be reached at startup. Every read
// misses and every write is dropped, so the semantic and direct cache layers
// quietly do nothing - while the rest of the cache plugin (provider prompt
// caching, hallucination control) keeps running without a hard dependency on
// Redis/Qdrant/etc. Reporting RequiresVectors() == false also keeps the plugin
// off the embedding path entirely.
type noopStore struct{}

// NewNoopStore returns a vector store that does nothing. Use it to keep the
// gateway up when the real store is unavailable instead of failing to boot.
func NewNoopStore() VectorStore { return noopStore{} }

func (noopStore) Ping(context.Context) error { return nil }

func (noopStore) CreateNamespace(context.Context, string, int, map[string]VectorStoreProperties) error {
	return nil
}

func (noopStore) DeleteNamespace(context.Context, string) error { return nil }

func (noopStore) GetChunk(context.Context, string, string) (SearchResult, error) {
	return SearchResult{}, ErrNotFound
}

func (noopStore) GetChunks(context.Context, string, []string) ([]SearchResult, error) {
	return nil, nil
}

func (noopStore) GetAll(context.Context, string, []Query, []string, *string, int64) ([]SearchResult, *string, error) {
	return nil, nil, nil
}

func (noopStore) GetNearest(context.Context, string, []float32, []Query, []string, float64, int64) ([]SearchResult, error) {
	return nil, nil
}

func (noopStore) RequiresVectors() bool { return false }

func (noopStore) Add(context.Context, string, string, []float32, map[string]interface{}) error {
	return nil
}

func (noopStore) Delete(context.Context, string, string) error { return nil }

func (noopStore) DeleteAll(context.Context, string, []Query) ([]DeleteResult, error) {
	return nil, nil
}

func (noopStore) Close(context.Context, string) error { return nil }
