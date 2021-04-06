package main

import (
	_ "embed"
	"fmt"
	"os"
	"ssh-key-exchange/src/helper"
	"ssh-key-exchange/src/sshkeys"
	"strings"
)

// https://stackoverflow.com/questions/13904441/whats-the-best-way-to-bundle-static-resources-in-a-go-program
//go:embed version_git_tag
var version string

func main() {
	version = strings.TrimSuffix(version, "\n")
	var args = helper.HandleArgs(version)

	sshkeys.HandleRSAKeys(*args.RsaPrivPath, *args.RsaPubPath, *args.RsaKeyGenerate)

	var success = false

	var summaryList []*helper.Summary
	for _, host := range helper.ResolveRemoteHostIpAddresses(*args.Host, args.Range, args.Exclude) {
		var summary *helper.Summary
		if *args.Delete {
			summary = sshkeys.DeleteKey(host, args)
		} else {
			summary = sshkeys.DistributeKey(host, args)
		}
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
