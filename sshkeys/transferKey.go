package sshkeys

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"os"
	"ssh-key-exchange/helper"
	"strings"
	"syscall"
	"time"
)

type ConnectionConfig struct {
	Host string
	User string
	Port string
}

// distribute the public key to the remote server and check it afterwards
func DistributeKey(host string, args *helper.Args) *helper.Summary {
	summary := &helper.Summary{Host: host, Success: true, Action: "ADD"}

	log.Println("check: " + host)
	if checkTcpPort(host, *args.Port, 120*time.Millisecond) {
		config := &ConnectionConfig{Host: host, User: *args.User, Port: *args.Port}
		if successful, err := checkKeyAuthentication(config, *args.RsaPrivPath); !successful {
			if err != nil {
				summary.Success = false
				summary.Message = err.Error()
				return summary
			}
			if args.Password == nil || *args.Password == "" {
				fmt.Print("Enter Password: ")
				bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
				println("")
				if err != nil {
					panic(err)
				}
				password := string(bytePassword)
				args.Password = &password
			}

			if _, err := transferPublicKey(config, *args.Password, *args.RsaPubPath); err != nil {
				summary.Success = false
				summary.Message = err.Error()
			} else {
				summary.Success, _ = checkKeyAuthentication(config, *args.RsaPrivPath)
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

// check if the key based login works
func checkKeyAuthentication(config *ConnectionConfig, rsaPrivPath string) (bool, error) {
	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			publicKeyFile(rsaPrivPath),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}

	connection, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	if err != nil {
		if strings.Contains(err.Error(), "ssh: unable to authenticate") {
			return false, nil
		}
		return false, err
	}
	defer connection.Close()

	return true, nil
}

// check whether a socket connection can be established or not
func checkTcpPort(host string, port string, timeout time.Duration) bool {
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

// executeCmd
// execute command on remote computer
func executeCmd(client *ssh.Client, command string) {
	session, _ := client.NewSession()
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	if err := session.Run(command); err != nil {
		log.Println(err.Error())
	}
}

// publicKeyFile returns an ssh.AuthMethod read from the given public key file
func publicKeyFile(rsaPrivPath string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(rsaPrivPath)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

// transferPublicKey geneates the script for copiing the public key to the remote computer,#
// copy the script and execute it
func transferPublicKey(config *ConnectionConfig, password string, rsaPubPath string) (bool, error) {
	log.Println("transferPublicKey")
	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	if err != nil {
		return false, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	script := createRemoteScriptForAddingKey(rsaPubPath, config.User)
	if _, err = copyRemoteScript(client, script); err != nil {
		return false, err
	}
	executeCmd(client, "env sh "+script.RemotePath)

	return true, nil
}
