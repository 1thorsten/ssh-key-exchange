package localHelper

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"sort"
	"ssh-key-exchange/sshHelper"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// look for RSA keys in the given path. If the files doesn't exist create them on demand
func HandleRSAKeys(rsaPrivPath string, rsaPubPath string, createIfNotExisting bool) {
	if (!existsFileOrDir(rsaPrivPath) || !existsFileOrDir(rsaPubPath)) && createIfNotExisting {
		if dirname := path.Dir(rsaPrivPath); !existsFileOrDir(dirname) {
			if err := os.MkdirAll(dirname, 0600); err != nil {
				log.Fatal(err.Error())
			}
		}

		if dirname := path.Dir(rsaPubPath); !existsFileOrDir(dirname) {
			if err := os.MkdirAll(dirname, 0600); err != nil {
				log.Fatal(err.Error())
			}
		}
		start := time.Now()
		bitSize := 4096

		privateKey, err := generatePrivateKey(bitSize)
		if err != nil {
			log.Fatal(err.Error())
		}

		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err.Error())
		}

		privateKeyBytes := encodePrivateKeyToPEM(privateKey)

		log.Printf("generate Keys in %s\n", time.Since(start))
		if err := ioutil.WriteFile(rsaPrivPath, privateKeyBytes, 0600); err != nil {
			log.Fatal(err.Error())
		}

		log.Printf("private key saved to: %s", rsaPrivPath)

		if err := ioutil.WriteFile(rsaPubPath, publicKeyBytes, 0600); err != nil {
			log.Fatal(err.Error())
		}
		log.Printf("public key saved to: %s", rsaPubPath)
	}
}

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
		remoteIpAddresses = append(remoteIpAddresses, ipAddress)
	}

	return remoteIpAddresses
}

// check whether a socket connection can be established or not
func CheckTcpPort(host string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

// status summary
type Summary struct {
	Host    string
	Success bool
	Message string
}

// summarize status and message
func (s Summary) Status() string {
	var status = "OK"
	if s.Success == false {
		status = "FAILED"
	}

	if len(s.Message) > 0 {
		status += " - " + s.Message
	}

	return status
}

// distribute the public key to the remote server and check it afterwards
func DistributeKey(host string, args Args) *Summary {
	summary := &Summary{Host: host, Success: true}

	log.Println("check: " + host)
	if CheckTcpPort(host, *args.Port, 120*time.Millisecond) {
		config := &sshHelper.ConnectionConfig{Host: host, User: *args.User, Port: *args.Port}
		if successful, err := sshHelper.CheckKeyAuthentication(config, *args.RsaPrivPath); !successful {
			if err != nil {
				summary.Success = false
				summary.Message = err.Error()
				return summary
			}
			if args.Password == nil || *args.Password == "" {
				fmt.Print("Enter Password: ")
				bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
				if err != nil {
					panic(err)
				}
				password := string(bytePassword)
				args.Password = &password
			}

			if _, err := sshHelper.TransferPublicKey(config, *args.Password, *args.RsaPubPath); err != nil {
				summary.Success = false
				summary.Message = err.Error()
			} else {
				summary.Success, _ = sshHelper.CheckKeyAuthentication(config, *args.RsaPrivPath)
			}
			return summary
		}

		summary.Message = "has already been set up"
		return summary
	} else {
		summary.Success = false
		summary.Message = fmt.Sprintf("Port (%s) is not open", *args.Port)
	}
	return summary
}
