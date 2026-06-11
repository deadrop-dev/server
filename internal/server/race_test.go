package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// TestBurnRaceOverHTTP is the end-to-end SPEC §3 check: N concurrent
// correct-key GETs against a live HTTP server must yield exactly one 200
// (with the payload) and 404 for all the rest — across many iterations.
func TestBurnRaceOverHTTP(t *testing.T) {
	const workers = 6
	const iterations = 20

	e := newTestEnv(t, nil)
	for i := 0; i < iterations; i++ {
		id := fmt.Sprintf("%032d", i)
		resp, _ := e.post(t, createBody(map[string]any{"id": id}))
		wantStatus(t, resp, 201)

		url := e.srv.URL + "/api/secrets/" + id + "?k=" + testKeyHash
		start := make(chan struct{})
		type result struct {
			status int
			body   string
		}
		results := make(chan result, workers)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				resp, err := http.Get(url)
				if err != nil {
					results <- result{status: -1}
					return
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				results <- result{status: resp.StatusCode, body: string(b)}
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		var ok200, notFound int
		for r := range results {
			switch r.status {
			case 200:
				ok200++
				if r.body == "" || !strings.Contains(r.body, testEnc) {
					t.Errorf("iteration %d: 200 response missing payload: %q", i, r.body)
				}
			case 404:
				notFound++
			default:
				t.Fatalf("iteration %d: unexpected status %d", i, r.status)
			}
		}
		if ok200 != 1 || notFound != workers-1 {
			t.Fatalf("iteration %d: got %d×200 and %d×404, want exactly 1×200 and %d×404",
				i, ok200, notFound, workers-1)
		}
	}
}
