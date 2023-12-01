package tool

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ChristianSch/titan/reporting"
	"github.com/Ullaakut/nmap"
)

func EnumAnonymousFtp(target string) []reporting.Discovery {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tcpScanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithContext(ctx),
		nmap.WithScripts("ftp-anon"),
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
				if script.ID == "ftp-anon" {
					head := script.Output
					tail := script.Output

					if strings.Contains(script.Output, "\n") {
						head = strings.Split(script.Output, "\n")[0]
						tail = strings.Join(strings.Split(script.Output, "\n")[1:], "\n")
					}

					discoveries = append(discoveries, reporting.Discovery{
						Target:           target,
						AffectedResource: fmt.Sprintf("%s (%d)", port.Service.Name, port.ID),
						Summary:          head,
						Description:      tail,
						Score:            reporting.SeverityHigh,
					})
				} else {
					fmt.Println("script id: ", script.ID)
				}
			}
		}
	}

	return discoveries
}
