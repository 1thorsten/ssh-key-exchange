# ssh-key-exchange
ssh-key-exchange (ske) changes the way you set up key-based ssh communication between two or more computers.
ske performs all the necessary steps that you must perform before key-based authentication can begin.

1. ske generates the necessary private and public key for the computer on which ske is started (it also takes an existing key pair).
2. ske connects to the remote computer via password and adds the public key to the authorized keys
3. then ske checks whether the key-based authentication works or not
4. you can define a range of remote computers for which key-based authentication should be set up
5. at the end a short report is generated

# Build
for the local environemnt
```bash
make build
```
or (for all possible environments)
```bash
make build-all
```

# Example usage
You can try the various options ske offers with
```bash
ssh-key-exchange -h
```
To test ske you can use a netty ssh-server from docker-hub
```bash
# first terminal
docker run --rm --publish=2222:22 --name ssh-server-local sickp/alpine-sshd:latest

# second terminal
bin/ssh-key-exchange --host 127.0.0.1 --port 2222 --user root --rsaKeyGenerate --rsaPrivPath ./id_rsa --rsaPubPath ./idrsa.pub
```
Stopping the ssh-server as follows:
````bash
docker stop ssh-server-local
````

# Download
You can also just download the latest release from [here](https://github.com/1thorsten/ssh-key-exchange/releases).
