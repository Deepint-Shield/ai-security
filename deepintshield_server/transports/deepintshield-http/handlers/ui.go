package handlers

import (
	"embed"
	"mime"
	"path"
	"path/filepath"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

// UIHandler handles UI routes.
type UIHandler struct {
	uiContent embed.FS
}

// NewUIHandler creates a new UIHandler instance.
func NewUIHandler(uiContent embed.FS) *UIHandler {
	return &UIHandler{
		uiContent: uiContent,
	}
}

// RegisterRoutes registers the UI routes with the provided router.
func (h *UIHandler) RegisterRoutes(router *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	router.GET("/", lib.ChainMiddlewares(h.serveDashboard, middlewares...))
	router.GET("/{filepath:*}", lib.ChainMiddlewares(h.serveDashboard, middlewares...))
}

// ServeDashboard serves the dashboard UI.
func (h *UIHandler) serveDashboard(ctx *fasthttp.RequestCtx) {
	// Get the request path
	requestPath := string(ctx.Path())

	// Clean the path to prevent directory traversal
	cleanPath := path.Clean(requestPath)

	// Handle .txt files (Next.js RSC payload files) - map from /{page}.txt to /{page}/index.txt
	if strings.HasSuffix(cleanPath, ".txt") {
		// Remove .txt extension and add /index.txt
		basePath := strings.TrimSuffix(cleanPath, ".txt")
		if basePath == "/" || basePath == "" {
			basePath = "/index"
		}
		cleanPath = basePath + "/index.txt"
	}

	// Remove leading slash and add ui prefix
	if cleanPath == "/" {
		cleanPath = "ui/index.html"
	} else {
		cleanPath = "ui" + cleanPath
	}

	// Block hidden directories and files (any path segment starting with .)
	segments := strings.Split(cleanPath, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, ".") {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - Not found")
			return
		}
	}

	// Block sensitive files
	baseName := filepath.Base(cleanPath)
	sensitiveFiles := []string{"package.json", "package-lock.json"}
	for _, sensitive := range sensitiveFiles {
		if baseName == sensitive {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - Not found")
			return
		}
	}

	// Check if this is a static asset request (has file extension)
	hasExtension := strings.Contains(filepath.Base(cleanPath), ".")

	// Try to read the file from embedded filesystem
	data, err := h.uiContent.ReadFile(cleanPath)
	if err != nil {

		// If it's a static asset (has extension) and not found, return 404
		if hasExtension {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - Static asset not found: " + requestPath)
			return
		}

		// For routes without extensions (SPA routing), try {path}/index.html first
		if !hasExtension {
			indexPath := cleanPath + "/index.html"
			data, err = h.uiContent.ReadFile(indexPath)
			if err == nil {
				cleanPath = indexPath
			} else {
				// If that fails, serve root index.html as fallback
				data, err = h.uiContent.ReadFile("ui/index.html")
				if err != nil {
					ctx.SetStatusCode(fasthttp.StatusNotFound)
					ctx.SetBodyString("404 - File not found")
					return
				}
				cleanPath = "ui/index.html"
			}
		} else {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - File not found")
			return
		}
	}

	// Set content type based on file extension
	ext := filepath.Ext(cleanPath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx.SetContentType(contentType)

	// Set cache headers based on whether the response is content-hashed.
	//
	// `_next/static/` files are content-hashed by Next.js (e.g.
	// `webpack-028dc81…js`), so they can be cached forever - the URL
	// changes on every rebuild.
	//
	// HTML entry points and `.txt` RSC payloads embed those chunk hashes
	// inline. After a deploy the new HTML/RSC references new chunk hashes
	// and the old ones disappear from disk. If a browser revives a cached
	// HTML/RSC pointing at vanished chunks, the webpack runtime throws
	// "Cannot read properties of undefined (reading 'call')" on first
	// import - which is what we want to prevent. The strict no-store
	// directive forces the browser (and any intermediate proxy) to fetch
	// the entry from origin every time.
	switch {
	case strings.HasPrefix(cleanPath, "ui/_next/static/"):
		ctx.Response.Header.Set("Cache-Control", "public, max-age=31536000, immutable")
	case ext == ".html", ext == ".txt", ext == ".json":
		ctx.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		ctx.Response.Header.Set("Pragma", "no-cache")
		ctx.Response.Header.Set("Expires", "0")
	default:
		ctx.Response.Header.Set("Cache-Control", "public, max-age=3600")
	}

	// Send the file content
	ctx.SetBody(data)
}
