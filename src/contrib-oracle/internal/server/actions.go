package server

import (
	"encoding/json"
	"fmt"
	"strings"
)

// processEvent centralizes action handling and rewards.
func (s *Server) processEvent(event string, obj map[string]any, repoFull string) string {
    switch event {
    case "pull_request":
        if pr, ok := obj["pull_request"].(map[string]any); ok {
            merged, _ := pr["merged"].(bool)
            state, _ := pr["state"].(string)
            if state == "closed" && merged {
                number := numberFrom(pr["number"]) 
                key := fmt.Sprintf("pr_merged:%s:%d", repoFull, number)
                if !s.markSeen(key) { return "ignored" }
                user := extractLogin(pr, "user")
                amount := s.rewardForPR(pr)
                if user != "" && amount > 0 {
                    if err := s.mintFor(user, amount); err == nil { return "minted" }
                }
            }
        }
        return "ignored"

    case "issues":
        if action, _ := obj["action"].(string); action == "closed" {
            if issue, ok := obj["issue"].(map[string]any); ok {
                number := numberFrom(issue["number"]) 
                key := fmt.Sprintf("issue_closed:%s:%d", repoFull, number)
                if !s.markSeen(key) { return "ignored" }
                user := extractLogin(obj, "sender")
                if user == "" { user = extractLogin(issue, "user") }
                if user != "" {
                    if err := s.mintFor(user, 25); err == nil { return "minted" }
                }
            }
        }
        return "ignored"

    case "pull_request_review":
        if review, ok := obj["review"].(map[string]any); ok {
            state, _ := review["state"].(string)
            if strings.EqualFold(state, "approved") {
                pr := obj["pull_request"].(map[string]any)
                number := numberFrom(pr["number"]) 
                id := numberFrom(review["id"]) 
                key := fmt.Sprintf("pr_review_approved:%s:%d:%d", repoFull, number, id)
                if !s.markSeen(key) { return "ignored" }
                user := extractLogin(review, "user")
                if user != "" {
                    if err := s.mintFor(user, 10); err == nil { return "minted" }
                }
            }
        }
        return "ignored"

    case "push":
        if ref, _ := obj["ref"].(string); strings.HasSuffix(ref, "/main") {
            if commits, ok := obj["commits"].([]any); ok {
                minted := false
                for _, ci := range commits {
                    if cmt, ok := ci.(map[string]any); ok {
                        id, _ := cmt["id"].(string)
                        added := arrayLen(cmt["added"]) 
                        modified := arrayLen(cmt["modified"]) 
                        if added+modified == 0 { continue }
                        author := extractLogin(cmt, "author")
                        if author == "" {
                            if committer, ok := cmt["committer"].(map[string]any); ok {
                                if u, ok := committer["username"].(string); ok { author = u }
                            }
                        }
                        if author == "" || s.isMaintainer(author) { continue }
                        key := fmt.Sprintf("push_commit:%s:%s", repoFull, id)
                        if !s.markSeen(key) { continue }
                        if err := s.mintFor(author, 50); err == nil { minted = true }
                    }
                }
                if minted { return "minted" }
            }
        }
        return "ignored"
    }
    return "ignored"
}

func extractLogin(obj map[string]any, field string) string {
    if user, ok := obj[field].(map[string]any); ok {
        if login, ok := user["login"].(string); ok { return login }
        if u, ok := user["username"].(string); ok { return u }
    }
    return ""
}

func numberFrom(v any) int64 {
    switch t := v.(type) {
    case float64:
        return int64(t)
    case int64:
        return t
    case json.Number:
        i, _ := t.Int64(); return i
    default:
        return 0
    }
}

func arrayLen(v any) int {
    if a, ok := v.([]any); ok { return len(a) }
    return 0
}

func (s *Server) rewardForPR(pr map[string]any) uint64 {
    if hasDocLabel(pr) { return 25 }
    return 100
}

func hasDocLabel(pr map[string]any) bool {
    if labels, ok := pr["labels"].([]any); ok {
        for _, li := range labels {
            if m, ok := li.(map[string]any); ok {
                if n, ok := m["name"].(string); ok {
                    ln := strings.ToLower(n)
                    if ln == "docs" || ln == "documentation" { return true }
                }
            }
        }
    }
    if t, ok := pr["title"].(string); ok {
        lt := strings.ToLower(t)
        if strings.Contains(lt, "[docs]") || strings.Contains(lt, "docs:") { return true }
    }
    return false
}
