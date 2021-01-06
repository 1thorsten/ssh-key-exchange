package sshkeys

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type ScriptResult struct {
	LocalPath  string
	RemotePath string
	Content    string
}

// createRemoteScript
// create the script for the remote computer (copies the public key)
func createRemoteScript(rsaPubPath string, user string) *ScriptResult {
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	random := strconv.Itoa(seededRand.Int())
	baseName := "ssh-script." + random
	localPath := os.TempDir() + string(os.PathSeparator) + baseName
	remotePath := "/tmp/" + baseName
	_rsaPubKey, _ := ioutil.ReadFile(rsaPubPath)

	data := &map[string]string{
		"User":     user,
		"Backtick": "`",
		"Key":      strings.TrimSpace(string(_rsaPubKey)),
		"File":     remotePath,
	}
	content := `\
        mkdir -p ~{{.User}}/.ssh
        
        {{/* ensure availability of authorized_keys */}}
        touch ~{{.User}}/.ssh/authorized_keys

        {{/* avoid adding the same key multiple times */}}
        COUNT={{.Backtick}}cat ~{{.User}}/.ssh/authorized_keys | grep -i '{{.Key}}' | wc -l{{.Backtick}}
        
		if [ "$COUNT" -eq 0 ]; then
          printf '\n{{.Key}}\n' >> ~{{.User}}/.ssh/authorized_keys
        fi
        
        {{/* remove this script */}}
        rm {{.File}}`

	var buf bytes.Buffer
	t, _ := template.New("remoteScript").Parse(content)
	_ = t.Execute(&buf, data)

	return &ScriptResult{LocalPath: localPath, RemotePath: remotePath, Content: buf.String()}
}

// copyRemoteScript
// copies the generated script to the remote computer
func copyRemoteScript(client *ssh.Client, script *ScriptResult) (bool, error) {
	if err := ioutil.WriteFile(script.LocalPath, []byte(script.Content), 0644); err != nil {
		log.Printf("could not write file '%s' -> %s\n", script.LocalPath, err.Error())
		return false, err
	}
	defer os.Remove(script.LocalPath)

	// https://stackoverflow.com/questions/53256373/sending-file-over-ssh-in-go
	file, err := os.Open(script.LocalPath)
	if err != nil {
		log.Printf("could not open file '%s' -> %s\n", script.LocalPath, err.Error())
		return false, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		log.Printf("could not read file structure from '%s' -> %s\n", script.LocalPath, err.Error())
		return false, err
	}

	session, err := client.NewSession()
	if err != nil {
		log.Printf("could open new ssh-session to '%s' -> %s\n", client.Conn.RemoteAddr(), err.Error())
		return false, err
	}
	defer session.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)

	// https://www.atatus.com/blog/goroutines-error-handling/
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		defer wg.Done()
		hostIn, err := session.StdinPipe()
		if err != nil {
			log.Printf("could not open ssh stdin pipe -> %s\n", err.Error())
			errs <- err
			return
		}
		defer hostIn.Close()
		if _, err := fmt.Fprintf(hostIn, "C0664 %d %s\n", stat.Size(), path.Base(script.RemotePath)); err != nil {
			log.Printf("could send start signal -> %s\n", err.Error())
			errs <- err
			return
		}
		if _, err := io.Copy(hostIn, file); err != nil {
			log.Printf("could copy file '%s' to stdin pipe -> %s\n", script.LocalPath, err.Error())
			errs <- err
			return
		}
		if _, err := fmt.Fprint(hostIn, "\x00"); err != nil {
			log.Printf("could send stop signal -> %s\n", err.Error())
			errs <- err
			return
		}

	}()

	errScp := session.Run("/usr/bin/scp -t " + path.Dir(script.RemotePath))
	wg.Wait()

	if err := <-errs; err != nil {
		return false, err
	}

	if errScp != nil {
		log.Printf("could copy file via scp to '%s' -> %s\n", script.RemotePath, errScp.Error())
		return false, errScp
	}

	return true, nil
}
