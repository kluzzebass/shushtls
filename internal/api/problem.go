package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

func writeStatusError(w http.ResponseWriter, err huma.StatusError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(err.GetStatus())
	_ = json.NewEncoder(w).Encode(err)
}

// registerAPINotFound returns RFC 9457 errors for unmatched /api/* requests.
func registerAPINotFound(mux *http.ServeMux, api huma.API) {
	spec := api.OpenAPI()

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if item := pathItemForRequest(spec, r.URL.Path); item != nil {
			allowed := allowedMethods(item)
			if !methodAllowed(r.Method, allowed) {
				w.Header().Set("Allow", strings.Join(allowed, ", "))
				detail := fmt.Sprintf("method %s not allowed for %s", r.Method, r.URL.Path)
				writeStatusError(w, huma.Error405MethodNotAllowed(detail))
				return
			}
		}

		detail := fmt.Sprintf("unknown API endpoint: %s %s", r.Method, r.URL.Path)
		writeStatusError(w, huma.Error404NotFound(detail))
	})
}

func pathItemForRequest(spec *huma.OpenAPI, path string) *huma.PathItem {
	if item := spec.Paths[path]; item != nil {
		return item
	}
	for pattern, item := range spec.Paths {
		if pathMatchesPattern(pattern, path) {
			return item
		}
	}
	return nil
}

func pathMatchesPattern(pattern, path string) bool {
	pSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	uSegs := strings.Split(strings.Trim(path, "/"), "/")
	if len(pSegs) != len(uSegs) {
		return false
	}
	for i, p := range pSegs {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			continue
		}
		if p != uSegs[i] {
			return false
		}
	}
	return true
}

func allowedMethods(item *huma.PathItem) []string {
	var methods []string
	if item.Get != nil {
		methods = append(methods, http.MethodGet)
	}
	if item.Put != nil {
		methods = append(methods, http.MethodPut)
	}
	if item.Post != nil {
		methods = append(methods, http.MethodPost)
	}
	if item.Delete != nil {
		methods = append(methods, http.MethodDelete)
	}
	if item.Patch != nil {
		methods = append(methods, http.MethodPatch)
	}
	if item.Head != nil {
		methods = append(methods, http.MethodHead)
	}
	if item.Options != nil {
		methods = append(methods, http.MethodOptions)
	}
	sort.Strings(methods)
	return methods
}

func methodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}
