package tool

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/ChristianSch/titan/reporting"
	"github.com/Ullaakut/nmap"
)

func DetectOS(target string) *reporting.Discovery {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcpScanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithContext(ctx),
		nmap.WithOSDetection(),
		nmap.WithOSScanGuess(),
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	tcpResult, warnings, err := tcpScanner.Run()
	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if len(tcpResult.Hosts) == 0 || len(tcpResult.Hosts[0].OS.Matches) == 0 {
		return nil
	}

	return &reporting.Discovery{
		Target:           target,
		AffectedResource: "Operating System",
		Summary:          "Operating System detected",
		Description:      tcpResult.Hosts[0].OS.Matches[0].Name,
		Score:            reporting.SeverityInfo,
	}
}

func DetectServices(target string) []reporting.Discovery {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tcpScanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithContext(ctx),
		nmap.WithSYNScan(), // force TCP SYN scan, fails if not privileged
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithScripts("vulners"),
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	tcpResult, warnings, err := tcpScanner.Run()
	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	discoveries := make([]reporting.Discovery, 0)

	// add ports to discoveries
	for _, host := range tcpResult.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" && port.State.State != "open|filtered" {
				continue
			}

			discoveries = append(discoveries, reporting.Discovery{
				Target:           target,
				AffectedResource: "Service",
				Summary:          fmt.Sprintf("Service running %d", port.ID),
				Description:      port.Service.Name,
				Score:            reporting.SeverityInfo,
			})

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					for _, table := range script.Tables {
						for _, tbl := range table.Tables {
							id := scriptValueForKey(tbl, "id")
							vulnType := scriptValueForKey(tbl, "type")
							score := scriptValueForKey(tbl, "cvss")
							scoreF, _ := strconv.ParseFloat(score, 32)
							sev := reporting.RankSeverity(float32(scoreF))

							discoveries = append(discoveries, reporting.Discovery{
								Target:           target,
								AffectedResource: fmt.Sprintf("%s (%d)", port.Service.Name, port.ID),
								Summary:          "Vulnerability found",
								Description:      fmt.Sprintf("%s: %s  [%f]", id, vulnType, scoreF),
								Score:            sev,
							})
						}
					}
				} else {
					println("script id: ", script.ID)
				}
			}
		}
	}

	return discoveries
}

func scriptValueForKey(tbl nmap.Table, key string) string {
	for _, row := range tbl.Elements {
		if row.Key == key {
			return row.Value
		}
	}

	return ""
}
