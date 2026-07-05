package table

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Test_bduIdentifier(t *testing.T) {
	tests := []struct {
		name      string
		vendorIDs []string
		want      string
	}{
		{"один BDU", []string{"BDU:2021-05969"}, "BDU:2021-05969"},
		{"BDU среди прочих", []string{"RHSA-2021:0001", "BDU:2021-05969"}, "BDU:2021-05969"},
		{"без BDU", []string{"RHSA-2021:0001"}, ""},
		{"пусто", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bduIdentifier(tt.vendorIDs))
		})
	}
}

// Проверяем, что идентификатор БДУ отображается в колонке Vulnerability.
func Test_vulnerabilityRenderer_BDU(t *testing.T) {
	result := types.Result{
		Target: "test",
		Class:  types.ClassLangPkg,
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID:  "CVE-2021-44228",
				VendorIDs:        []string{"BDU:2021-05969"},
				PkgName:          "log4j-core",
				InstalledVersion: "2.14.1",
				FixedVersion:     "2.15.0",
				Status:           dbTypes.StatusFixed,
				Vulnerability: dbTypes.Vulnerability{
					Title:    "Log4Shell",
					Severity: "CRITICAL",
				},
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	NewVulnerabilityRenderer(buf, false, false, false, []dbTypes.Severity{dbTypes.SeverityCritical}).Render(result)

	out := buf.String()
	assert.Contains(t, out, "CVE-2021-44228")
	assert.Contains(t, out, "BDU:2021-05969")
	// Идентификатор БДУ идёт отдельной строкой под CVE.
	assert.True(t, strings.Contains(out, "CVE-2021-44228") && strings.Contains(out, "BDU:2021-05969"),
		"вывод должен содержать и CVE, и BDU-ID")
}
