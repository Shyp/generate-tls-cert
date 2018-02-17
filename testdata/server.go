package main

import (
	"io"
	"net/http"

	"github.com/kevinburke/handlers"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello World")
	})
	http.ListenAndServeTLS(":7252", "leaf.pem", "leaf.key", handlers.Log(http.DefaultServeMux))
}
