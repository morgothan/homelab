package cf

// Compatibility adapter for upstream v0.3.0. IP lists still use the upstream
// client; firewall operations use Rulesets API endpoints and per-rule writes.
// Never PUT an entire ruleset: it may contain unrelated rules and new fields
// that the old cloudflare-go SDK cannot round-trip safely.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

const customPhase = "http_request_firewall_custom"

type rulesetsAPI struct {
	*cloudflare.API
	token   string
	client  *http.Client
	baseURL string
}

type modernRuleset struct {
	ID    string                   `json:"id"`
	Rules []map[string]interface{} `json:"rules"`
}

func stringField(rule map[string]interface{}, name string) string {
	value, _ := rule[name].(string)
	return value
}

type rulesetResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result modernRuleset `json:"result"`
}

func (api *rulesetsAPI) request(ctx context.Context, method, path string, body interface{}) (modernRuleset, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return modernRuleset{}, 0, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, api.baseURL+path, reader)
	if err != nil {
		return modernRuleset{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+api.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := api.client.Do(req)
	if err != nil {
		return modernRuleset{}, 0, err
	}
	defer res.Body.Close()
	var result rulesetResponse
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return modernRuleset{}, res.StatusCode, fmt.Errorf("rulesets API HTTP %d: invalid response", res.StatusCode)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !result.Success {
		return modernRuleset{}, res.StatusCode, fmt.Errorf("rulesets API HTTP %d: %v", res.StatusCode, result.Errors)
	}
	return result.Result, res.StatusCode, nil
}

func (api *rulesetsAPI) ruleset(ctx context.Context, zone string) (modernRuleset, error) {
	result, status, err := api.request(ctx, http.MethodGet, "/zones/"+zone+"/rulesets/phases/"+customPhase+"/entrypoint", nil)
	if status == http.StatusNotFound {
		return modernRuleset{}, nil
	}
	return result, err
}

func legacyRules(rs modernRuleset) []cloudflare.FirewallRule {
	rules := make([]cloudflare.FirewallRule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		rules = append(rules, cloudflare.FirewallRule{ID: stringField(r, "id"), Action: stringField(r, "action"), Description: stringField(r, "description"), Paused: r["enabled"] == false,
			Filter: cloudflare.Filter{ID: stringField(r, "id"), Expression: stringField(r, "expression")}})
	}
	return rules
}

func (api *rulesetsAPI) FirewallRules(ctx context.Context, zone string, _ cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error) {
	rs, err := api.ruleset(ctx, zone)
	return legacyRules(rs), err
}

func (api *rulesetsAPI) CreateFirewallRules(ctx context.Context, zone string, rules []cloudflare.FirewallRule) ([]cloudflare.FirewallRule, error) {
	rs, err := api.ruleset(ctx, zone)
	if err != nil {
		return nil, err
	}
	created := make([]cloudflare.FirewallRule, 0, len(rules))
	for _, r := range rules {
		rule := map[string]interface{}{"expression": r.Filter.Expression, "action": r.Action, "description": r.Description, "enabled": true}
		path := "/zones/" + zone + "/rulesets"
		var body interface{} = rule
		if rs.ID == "" {
			body = map[string]interface{}{"name": "Zone custom firewall rules", "kind": "zone", "phase": customPhase, "rules": []interface{}{rule}}
		} else {
			path += "/" + rs.ID + "/rules"
		}
		rs, _, err = api.request(ctx, http.MethodPost, path, body)
		if err != nil {
			return nil, err
		}
		found := false
		for _, candidate := range legacyRules(rs) {
			if candidate.Filter.Expression == r.Filter.Expression && candidate.Action == r.Action && candidate.Description == r.Description && !candidate.Paused {
				created = append(created, candidate)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("created rule missing from Cloudflare response")
		}
	}
	return created, nil
}

func (api *rulesetsAPI) UpdateFilters(ctx context.Context, zone string, filters []cloudflare.Filter) ([]cloudflare.Filter, error) {
	rs, err := api.ruleset(ctx, zone)
	if err != nil {
		return nil, err
	}
	for _, filter := range filters {
		var body map[string]interface{}
		for _, r := range rs.Rules {
			if stringField(r, "id") == filter.ID {
				body = r
				break
			}
		}
		if body == nil {
			return nil, fmt.Errorf("rule %s is missing from zone ruleset", filter.ID)
		}
		// PATCH replaces the rule definition, so preserve all writable fields,
		// including fields added after the upstream SDK was released.
		delete(body, "id")
		delete(body, "version")
		delete(body, "last_updated")
		body["expression"] = filter.Expression
		_, _, err = api.request(ctx, http.MethodPatch, "/zones/"+zone+"/rulesets/"+rs.ID+"/rules/"+filter.ID,
			body)
		if err != nil {
			return nil, err
		}
	}
	return filters, nil
}

func (api *rulesetsAPI) Filters(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.Filter, error) {
	rules, err := api.FirewallRules(ctx, zone, opts)
	filters := make([]cloudflare.Filter, 0, len(rules))
	for _, rule := range rules {
		filters = append(filters, rule.Filter)
	}
	return filters, err
}

func (api *rulesetsAPI) DeleteFirewallRules(ctx context.Context, zone string, ids []string) error {
	rs, err := api.ruleset(ctx, zone)
	if err != nil {
		return err
	}
	for _, id := range ids {
		_, _, err = api.request(ctx, http.MethodDelete, "/zones/"+zone+"/rulesets/"+rs.ID+"/rules/"+id, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (api *rulesetsAPI) DeleteFilters(ctx context.Context, zone string, ids []string) error {
	// Modern expressions belong to rules; there are no standalone filter objects.
	return api.DeleteFirewallRules(ctx, zone, ids)
}

func newRulesetsAPI(api *cloudflare.API, token string) cloudflareAPI {
	if wafToken := os.Getenv("CF_CROWDSEC_WAF_TOKEN"); wafToken != "" {
		token = wafToken
	}
	return &rulesetsAPI{API: api, token: token, client: &http.Client{Timeout: 30 * time.Second}, baseURL: "https://api.cloudflare.com/client/v4"}
}
