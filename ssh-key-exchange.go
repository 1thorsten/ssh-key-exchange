package main

import (
	"fmt"
	local "ssh-key-exchange/localHelper"
)

func main() {
	var args = local.HandleArgs()

	local.HandleRSAKeys(*args.RsaPrivPath, *args.RsaPubPath, *args.RsaKeyGenerate)

	var summaryList []*local.Summary
	for _, host := range local.ResolveRemoteHostIpAddresses(*args.Host, args.Range, args.Exclude) {
		summary := local.DistributeKey(host, args)
		summaryList = append(summaryList, summary)
	}

	for _, s := range summaryList {
		fmt.Printf("%s\t -> %s\n", s.Host, s.Status())
	}

}
