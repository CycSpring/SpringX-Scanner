package web

import (
	"embed"
	"io/fs"
)

//go:embed assets/*
var embeddedAssets embed.FS

// assetFS returns the embedded assets rooted at assets/, exposed as the
// filesystem served under /static. The assets directory holds index.html,
// app.css and app.js.
func assetFS() fs.FS {
	sub, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}
