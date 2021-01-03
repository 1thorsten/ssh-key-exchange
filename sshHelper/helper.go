package sshHelper

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"strings"
	"time"
)

type ConnectionConfig struct {
	Host string
	User string
	Port string
}
type ScriptResult struct {
	LocalPath  string
	RemotePath string
	Content    string
}

// check if the key based login works
func CheckKeyAuthentication(config *ConnectionConfig, rsaPrivPath string) (bool, error) {
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

// transfer the public key to the remote server
func TransferPublicKey(config *ConnectionConfig, password string, rsaPubPath string) (bool, error) {
	log.Println("TransferPublicKey")
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

	script := createRemoteScript(rsaPubPath, config.User)
	if _, err = copyRemoteScript(client, script); err != nil {
		return false, err
	}
	executeCmd(client, "env sh "+script.RemotePath)

	return true, nil
}
