package lib

import (
	"fmt"
	"time"
)

// StartLoadingAnimation starts a loading animation in the terminal
// usage:
//
// stopChan := StartLoadingAnimation()
//
// // do work
//
// stopChan <- true
func StartLoadingAnimation() chan bool {
	stopChan := make(chan bool)

	go func() {
		for {
			select {
			case <-stopChan:
				// remove last loading character
				print("\r")
				return
			default:
				for _, r := range `-\|/` {
					fmt.Printf("\r%c", r)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}()

	return stopChan
}
