package lib

import "github.com/fatih/color"

func Bold(text string) {
	c := color.New(color.Bold)
	_, _ = c.Print(text)
}

func Green(text string) {
	c := color.New(color.FgGreen).Add(color.Bold)
	_, _ = c.Print(text)
}

func Yellow(text string) {
	c := color.New(color.FgYellow).Add(color.Bold)
	_, _ = c.Print(text)
}

func Red(text string) {
	c := color.New(color.FgRed).Add(color.Bold)
	_, _ = c.Print(text)
}
