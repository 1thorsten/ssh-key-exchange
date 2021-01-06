package main

import (
	"fmt"
	"io/ioutil"
	"ssh-key-exchange/helper"
	"ssh-key-exchange/sshkeys"
	"strings"
)

func readVersion() string {
	content, err := ioutil.ReadFile("version_git_tag")
	var version string
	if err != nil {
		version = "-version_git_tag is missing-"
	} else {
		version = string(content)
		version = strings.TrimSuffix(version, "\n")
	}

	return version
}

func main() {

	var args = helper.HandleArgs(readVersion())

	sshkeys.HandleRSAKeys(*args.RsaPrivPath, *args.RsaPubPath, *args.RsaKeyGenerate)

	var summaryList []*helper.Summary
	for _, host := range helper.ResolveRemoteHostIpAddresses(*args.Host, args.Range, args.Exclude) {
		summary := sshkeys.DistributeKey(host, args)
		summaryList = append(summaryList, summary)
	}

	for _, s := range summaryList {
		fmt.Printf("%s\t -> %s\n", s.Host, s.Status())
	}

}
