package helper

import (
	"fmt"
	"github.com/akamensky/argparse"
	"os"
	"path/filepath"
)

type Args struct {
	Host           *string
	Port           *string
	User           *string
	Password       *string
	RsaPrivPath    *string
	RsaPubPath     *string
	RsaKeyGenerate *bool
	Range          *string
	Exclude        *string
	//	Quiet		   *bool
}

// handle arguments from command-line
func HandleArgs(version string) *Args {
	home, found := os.LookupEnv("USERPROFILE")
	if !found {
		home = os.Getenv("HOME")
	}

	idRsa := filepath.FromSlash(home + "/.ssh/id_rsa")
	idRsaPub := filepath.FromSlash(idRsa + ".pub")

	// Create new parser object
	parser := argparse.NewParser("ssh-key-exchange (v"+version+")", "helps to exchange ssh-keys for key based ssh authentication")
	// Create string flag

	var args Args
	// https://github.com/akamensky/argparse
	args.Host = parser.String("i", "host", &argparse.Options{Required: true, Help: "Host ip (10.10.0.3) or in conjunction with range (10.20.0.X)"})
	args.Port = parser.String("P", "port", &argparse.Options{Required: false, Help: "port of ssh host", Default: "22"})
	args.User = parser.String("u", "user", &argparse.Options{Required: false, Help: "user of ssh host", Default: "root"})
	args.Password = parser.String("p", "password", &argparse.Options{Required: false, Help: "ssh password (if you do not specify it you will be asked)"})
	args.RsaPrivPath = parser.String("a", "rsaPrivPath", &argparse.Options{Required: false, Help: "path of id_rsa", Default: idRsa})
	args.RsaPubPath = parser.String("b", "rsaPubPath", &argparse.Options{Required: false, Help: "path of id_rsa.pub", Default: idRsaPub})
	args.RsaKeyGenerate = parser.Flag("k", "rsaKeyGenerate", &argparse.Options{Required: false, Help: "generate keys, base path is rsaPrivPath", Default: *args.RsaPrivPath == idRsa})
	args.Range = parser.String("r", "range", &argparse.Options{Required: false, Help: "range (1-6,8,13-233)"})
	args.Exclude = parser.String("e", "exclude", &argparse.Options{Required: false, Help: "comma separated list of excluded ip addresses (only in conjunction with range)"})
	//	args.Quiet = parser.Flag("q", "quiet", &argparse.Options{Required: false, Help: "suppress output", Default: false})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	return &args
}
