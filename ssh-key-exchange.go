package main

import (
	"fmt"
	"os"
	"ssh-key-exchange/helper"
	"ssh-key-exchange/sshkeys"
)

// https://stackoverflow.com/questions/13904441/whats-the-best-way-to-bundle-static-resources-in-a-go-program
//go:embed hello.txt / go 1.16
var version = "1.0.1"

func main() {
	var args = helper.HandleArgs(version)

	sshkeys.HandleRSAKeys(*args.RsaPrivPath, *args.RsaPubPath, *args.RsaKeyGenerate)

	var success = false

	var summaryList []*helper.Summary
	for _, host := range helper.ResolveRemoteHostIpAddresses(*args.Host, args.Range, args.Exclude) {
		summary := sshkeys.DistributeKey(host, args)
		if summary.Success {
			success = true
		}
		summaryList = append(summaryList, summary)
	}

	for _, s := range summaryList {
		fmt.Printf("%s\t -> %s\n", s.Host, s.Status())
	}

	if !success {
		os.Exit(1)
	}
}
