package cf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go"
)

func testAPI(t *testing.T, handler http.HandlerFunc) *rulesetsAPI {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &rulesetsAPI{token: "test-token", client: server.Client(), baseURL: server.URL}
}

func respond(w http.ResponseWriter, rules []cloudflare.RulesetRule) {
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": cloudflare.Ruleset{ID: "set", Rules: rules}})
}

func TestRulesetsImport(t *testing.T) {
	api := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/zones/zone/rulesets/phases/http_request_firewall_custom/entrypoint" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing authorization")
		}
		respond(w, []cloudflare.RulesetRule{{ID: "rule", Action: "block", Expression: "ip.src in $crowdsec_block", Description: "CrowdSec block rule", Enabled: true}, {ID: "disabled", Enabled: false}})
	})
	rules, err := api.FirewallRules(context.Background(), "zone", cloudflare.PaginationOptions{})
	if err != nil || len(rules) != 2 {
		t.Fatalf("import: %v %v", rules, err)
	}
	if rules[0].Filter.ID != "rule" || rules[0].Paused || !rules[1].Paused {
		t.Fatalf("incorrect mapping: %+v", rules)
	}
}

func TestRulesetsPatchPreservesOtherFields(t *testing.T) {
	patches := 0
	api := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`{"success":true,"result":{"id":"set","rules":[{"id":"owned","action":"block","expression":"old","description":"CrowdSec block rule","enabled":true,"ref":"stable-ref","future_field":{"keep":true},"version":"1","last_updated":"old"},{"id":"unrelated"}]}}`))
			return
		}
		if r.Method != "PATCH" || r.URL.Path != "/zones/zone/rulesets/set/rules/owned" {
			t.Errorf("unsafe write: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 6 || body["expression"] != "new expression" || body["action"] != "block" || body["enabled"] != true || body["ref"] != "stable-ref" || body["future_field"] == nil {
			t.Errorf("rule fields not preserved: %v", body)
		}
		patches++
		respond(w, nil)
	})
	_, err := api.UpdateFilters(context.Background(), "zone", []cloudflare.Filter{{ID: "owned", Expression: "new expression"}})
	if err != nil || patches != 1 {
		t.Fatalf("patch: %d %v", patches, err)
	}
	_, err = api.UpdateFilters(context.Background(), "zone", []cloudflare.Filter{{ID: "missing"}})
	if err == nil || patches != 1 {
		t.Fatal("missing rule should not be patched")
	}
}

func TestRulesetsCreate(t *testing.T) {
	for _, existing := range []bool{true, false} {
		t.Run(map[bool]string{true: "existing", false: "new"}[existing], func(t *testing.T) {
			api := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if existing {
						respond(w, []cloudflare.RulesetRule{{ID: "unrelated"}})
					} else {
						w.WriteHeader(404)
						w.Write([]byte(`{"success":false}`))
					}
					return
				}
				want := "/zones/zone/rulesets"
				if existing {
					want += "/set/rules"
				}
				if r.Method != "POST" || r.URL.Path != want {
					t.Errorf("unexpected write: %s %s", r.Method, r.URL.Path)
				}
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				if existing {
					if _, ok := body["rules"]; ok {
						t.Error("must not replace entire ruleset")
					}
					if body["enabled"] != true {
						t.Error("rule must be enabled")
					}
				} else if body["phase"] != customPhase || body["kind"] != "zone" {
					t.Errorf("incorrect entrypoint: %v", body)
				}
				respond(w, []cloudflare.RulesetRule{{ID: "created", Action: "block", Expression: "ip.src in $crowdsec_block", Description: "CrowdSec block rule", Enabled: true}})
			})
			rules, err := api.CreateFirewallRules(context.Background(), "zone", []cloudflare.FirewallRule{{Action: "block", Description: "CrowdSec block rule", Filter: cloudflare.Filter{Expression: "ip.src in $crowdsec_block"}}})
			if err != nil || len(rules) != 1 || rules[0].Filter.ID != "created" {
				t.Fatalf("create: %v %v", rules, err)
			}
		})
	}
}

func TestRulesetsPermissionFailureDoesNotCreate(t *testing.T) {
	api := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("must not mutate after authorization failure")
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	})
	_, err := api.CreateFirewallRules(context.Background(), "zone", []cloudflare.FirewallRule{{Action: "block"}})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("permission error missing: %v", err)
	}
}

func TestRulesetsDeleteOnlySpecifiedRule(t *testing.T) {
	deletes := 0
	api := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			respond(w, []cloudflare.RulesetRule{{ID: "owned"}, {ID: "unrelated"}})
			return
		}
		if r.Method != "DELETE" || r.URL.Path != "/zones/zone/rulesets/set/rules/owned" {
			t.Errorf("unsafe delete: %s %s", r.Method, r.URL.Path)
		}
		deletes++
		respond(w, nil)
	})
	if err := api.DeleteFirewallRules(context.Background(), "zone", []string{"owned"}); err != nil || deletes != 1 {
		t.Fatalf("delete: %d %v", deletes, err)
	}
}

func TestRulesetsSeparateCredential(t *testing.T) {
	t.Setenv("CF_CROWDSEC_WAF_TOKEN", "waf-token")
	api := newRulesetsAPI(nil, "list-token").(*rulesetsAPI)
	if api.token != "waf-token" {
		t.Fatal("WAF credential override not used")
	}
	t.Setenv("CF_CROWDSEC_WAF_TOKEN", "")
	api = newRulesetsAPI(nil, "list-token").(*rulesetsAPI)
	if api.token != "list-token" {
		t.Fatal("default credential not retained")
	}
}
