package helper

import (
	"sort"
	"strconv"
	"strings"
)

// resolve/calculate the ip addresses by the given arguments (range and exclude)
func ResolveRemoteHostIpAddresses(host string, rangeOfServers *string, exclude *string) []string {
	if strings.Index(host, "X") == -1 {
		return []string{host}
	}

	var ipHosts []int
	if rangeOfServers != nil {
		for _, s := range strings.Split(*rangeOfServers, ",") {
			// 9-13
			if trimmed := strings.TrimSpace(s); strings.Index(trimmed, "-") != -1 {
				rangeValues := strings.Split(trimmed, "-")
				result := makeRange(str2int(rangeValues[0]), str2int(rangeValues[1]))
				ipHosts = append(ipHosts, result...)
			} else {
				ipHosts = append(ipHosts, str2int(trimmed))
			}
		}
	}

	if exclude != nil && len(ipHosts) > 0 {
		for _, s := range strings.Split(*exclude, ",") {
			element2Remove := str2int(strings.TrimSpace(s))
			if contains, index := containsInt(ipHosts, element2Remove); contains == true {
				ipHosts = remove(ipHosts, index)
			}
		}
	}

	sort.Ints(ipHosts)

	var remoteIpAddresses []string
	for _, ip := range ipHosts {
		ipAddress := strings.Replace(host, "X", strconv.Itoa(ip), 1)
		if !containsStr(remoteIpAddresses, ipAddress) {
			remoteIpAddresses = append(remoteIpAddresses, ipAddress)
		}
	}

	return remoteIpAddresses
}

func str2int(value string) int {
	v, _ := strconv.Atoi(value)
	return v
}

func makeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

func containsInt(s []int, e int) (bool, int) {
	for index, a := range s {
		if a == e {
			return true, index
		}
	}
	return false, -1
}

func containsStr(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func remove(s []int, index int) []int {
	// replace element2remove with last element
	s[index] = s[len(s)-1]
	// shrink array by one element
	return s[:len(s)-1]
}
