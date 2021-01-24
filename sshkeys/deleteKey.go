package sshkeys

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"ssh-key-exchange/helper"
	"time"
)

func DeleteKey(host string, args *helper.Args) *helper.Summary {
	summary := &helper.Summary{Host: host, Success: true, Action: "DEL"}

	if checkTcpPort(host, *args.Port, 120*time.Millisecond) {
		config := &ConnectionConfig{Host: host, User: *args.User, Port: *args.Port}
		client, err := initiateKeyBasedConnectionAuthentication(config, *args.RsaPrivPath)
		if client != nil {
			defer client.Close()
		}
		if err != nil {
			summary.Success = false
			summary.Message = err.Error()
			return summary
		}

		script := createRemoteScriptForDeletingKey(*args.RsaPubPath, config.User)
		if _, err = copyRemoteScript(client, script); err != nil {
			summary.Success = false
			return summary
		}
		executeCmd(client, "env sh "+script.RemotePath)

		success, _ := checkKeyAuthentication(config, *args.RsaPrivPath)
		summary.Success = !success

		return summary
	} else {
		summary.Success = false
		summary.Message = fmt.Sprintf("Port (%s) is not open", *args.Port)
	}
	return summary
}

// try to establish a key based ssh connection
func initiateKeyBasedConnectionAuthentication(config *ConnectionConfig, rsaPrivPath string) (client *ssh.Client, err error) {
	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			publicKeyFile(rsaPrivPath),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}

	client, err = ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	return
}
