package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// TestClaimRaceOverHTTP is the end-to-end SPEC §9.3 check: N concurrent
// correct-proof claims against a live HTTP server must yield exactly one 200
// (with the blob) and 404 for all the rest — across many iterations.
func TestClaimRaceOverHTTP(t *testing.T) {
	const workers = 6
	const iterations = 20

	e := newTestEnv(t, nil)
	for i := 0; i < iterations; i++ {
		id := fmt.Sprintf("%032d", i)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"id": id}), nil)
		wantStatus(t, resp, 201)
		resp, _ = e.do(t, "POST", "/api/requests/"+id+"/response", fulfillBody(nil), nil)
		wantStatus(t, resp, 201)

		url := e.srv.URL + "/api/requests/" + id + "/response?proof=" + testClaimProof
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
					t.Errorf("iteration %d: 200 response missing blob: %q", i, r.body)
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

// TestFulfillRaceOverHTTP: N concurrent fulfills of the same request must
// yield exactly one 201 and 409 for all the rest (SPEC §9.2).
func TestFulfillRaceOverHTTP(t *testing.T) {
	const workers = 6
	const iterations = 20

	e := newTestEnv(t, nil)
	for i := 0; i < iterations; i++ {
		id := fmt.Sprintf("%032d", i)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"id": id}), nil)
		wantStatus(t, resp, 201)

		url := e.srv.URL + "/api/requests/" + id + "/response"
		start := make(chan struct{})
		results := make(chan int, workers)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				resp, err := http.Post(url, "application/json", strings.NewReader(fulfillBody(nil)))
				if err != nil {
					results <- -1
					return
				}
				resp.Body.Close()
				results <- resp.StatusCode
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		var created, conflicts int
		for status := range results {
			switch status {
			case 201:
				created++
			case 409:
				conflicts++
			default:
				t.Fatalf("iteration %d: unexpected status %d", i, status)
			}
		}
		if created != 1 || conflicts != workers-1 {
			t.Fatalf("iteration %d: got %d×201 and %d×409, want exactly 1×201 and %d×409",
				i, created, conflicts, workers-1)
		}
	}
}
