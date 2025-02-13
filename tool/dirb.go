package tool

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ChristianSch/titan/reporting"
)

// DirectoryBust performs directory busting using gobuster
func DirectoryBust(target string, wordlist string) ([]reporting.Discovery, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		fmt.Println("target mapped to: ", target, "(if you need to control the protocol, prefix the target with http:// or https://)")
	}

	cmd := exec.Command("gobuster", "dir", "-u", target, "-w", wordlist)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gobuster error: %v", err)
	}

	discoveries := []reporting.Discovery{}
	// scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Parse gobuster output
	// sanitize output
	input := string(output)

	fmt.Println("DBG input: ", input)
	re := regexp.MustCompile(`(?m)` + `(/[^\s]+)\s+\(Status: (\d+)\)[ ]*(.*)`)

	// Find all matches
	matches := re.FindAllStringSubmatch(input, -1)
	fmt.Println("DBG matches: ", matches)

	for _, match := range matches {
		path := match[1]
		status := match[2]
		description := match[3]

		if strings.Contains(description, "-->") {
			redirect := strings.Split(description, "-->")[1]
			redirect = strings.Trim(redirect, " ]")
			description += fmt.Sprintf("\nRedirects to: %s", redirect)
		}

		// Calculate severity based on status code
		severity := calculateSeverity(status)

		discoveries = append(discoveries, reporting.Discovery{
			Target:           target,
			AffectedResource: fmt.Sprintf("Web Directory: %s", path),
			Summary:          fmt.Sprintf("Found %s (Status: %s)", path, status),
			Description:      description,
			Score:            severity,
		})
	}

	if len(discoveries) == 0 {
		// If no paths were found, create a single discovery with the raw output
		discoveries = append(discoveries, reporting.Discovery{
			Target: target,
			// AffectedResource: "Web Directory",
			Summary: "No files found via dirb",
			// Description:      string(output),
			Score: reporting.SeverityInfo,
		})
	}

	return discoveries, nil
}

// calculateSeverity determines the severity of a finding based on the HTTP status code
func calculateSeverity(status string) reporting.Severity {
	switch status {
	case "200": // Direct hit
		return reporting.SeverityMedium
	case "301", "302", "303", "307", "308": // Redirects
		return reporting.SeverityLow
	case "401", "403": // Auth required/Forbidden
		return reporting.SeverityHigh
	default:
		return reporting.SeverityInfo
	}
}
