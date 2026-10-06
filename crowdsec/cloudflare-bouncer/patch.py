"""Apply checked, minimal hooks to the pinned upstream source."""
from pathlib import Path
p = Path('pkg/cf/cloudflare.go')
s = p.read_text()
changes = {
    'func NewCloudflareClient(token string, logger *log.Logger) (*cloudflare.API, error)':
    'func NewCloudflareClient(token string, logger *log.Logger) (cloudflareAPI, error)',
    'return z, err\n}':
    'if err != nil { return nil, err }; return newRulesetsAPI(z, token), nil\n}',
    'if strings.Contains(rule.Description, fmt.Sprintf("CrowdSec %s rule", action)) &&':
    'if !rule.Paused && rule.Action == action && strings.Contains(rule.Description, fmt.Sprintf("CrowdSec %s rule", action)) &&',
}
for old, new in changes.items():
    assert s.count(old) == 1, f'Upstream hook changed: {old}'
    s = s.replace(old, new)
p.write_text(s)
