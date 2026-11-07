// Package web embeds Keyhaven's HTML templates and static assets.
package web

import (
	"embed"
	"io/fs"
)

//go:embed templates/*.html
var Templates embed.FS

//go:embed static
var staticFS embed.FS

// Static serves the contents of the static directory.
var Static, _ = fs.Sub(staticFS, "static")
