// Command totpcheck prints the code the server would accept right now.
//
// It exists so a harness's TOTP implementation can be checked against the
// server's own rather than against a guess: a browser computing RFC 6238
// slightly wrong produces a refusal indistinguishable from a server bug, and
// the whole point of driving the flow by hand is to tell those apart.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	secret := flag.String("secret", "", "the base32 shared secret")
	flag.Parse()
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "totpcheck: -secret is required")
		os.Exit(1)
	}
	now := time.Now()
	code, err := totp.GenerateCode(*secret, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "totpcheck:", err)
		os.Exit(1)
	}
	fmt.Printf("code=%s step=%d\n", code, now.Unix()/30)
}
