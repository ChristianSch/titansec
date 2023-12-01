package reporting

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

// RankSeverity ranks the severity of a vulnerability based on its CVSS v3 score
func RankSeverity(score float32) Severity {
	// https://nvd.nist.gov/vuln-metrics/cvss
	if score >= 9.0 {
		return SeverityCritical
	} else if score >= 7.0 {
		return SeverityHigh
	} else if score >= 4.0 {
		return SeverityMedium
	} else if score >= 0.1 {
		return SeverityLow
	} else {
		return SeverityInfo
	}
}

// SeverityStr returns the string representation of a severity
func SeverityStr(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	case SeverityInfo:
		return "Info"
	default:
		return "Unknown"
	}
}

type Discovery struct {
	Target           string
	AffectedResource string
	Summary          string
	Description      string
	Score            Severity
}
