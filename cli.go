package main

// Client mode: "1time send" and "1time read" encrypt and decrypt on the
// machine that runs them, so the server never sees the plaintext. This is
// the replacement for /api/unsecSave in scripts.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"1time/internal/otcrypto"
)

const (
	defaultServer  = "https://onetime.j0ker.site"
	maxClientInput = 512 << 10
)

func runClient(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, clientUsage)
		return 2
	}
	var err error
	switch args[0] {
	case "send":
		err = clientSend(args[1:], stdin, stdout)
	case "read":
		err = clientRead(args[1:], stdout)
	default:
		fmt.Fprintln(stderr, clientUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "1time:", err)
		return 1
	}
	return 0
}

const clientUsage = `usage:
  1time send [-url URL] [-days N] < message      prints a one-time link
  1time read LINK                                prints the message once

Additional secret key: environment variable ONETIME_SECRET (not a flag,
so it does not show up in ps). Server: -url or ONETIME_URL, default ` + defaultServer + `.
Without arguments 1time runs the API server.`

var httpClient = &http.Client{Timeout: 30 * time.Second}

func postJSON(url string, in, out any) error {
	b, _ := json.Marshal(in)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return nil
}

func clientSend(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	server := fs.String("url", getenv("ONETIME_URL", defaultServer), "server URL")
	days := fs.Int("days", 7, "keep the message for N days (1..30)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *days < 1 || *days > 30 {
		return errors.New("-days must be 1..30")
	}
	msg, err := io.ReadAll(io.LimitReader(stdin, maxClientInput+1))
	if err != nil {
		return err
	}
	if len(msg) == 0 {
		return errors.New("empty message on stdin")
	}
	if len(msg) > maxClientInput {
		return errors.New("message is larger than 512 KB")
	}
	linkKey, err := otcrypto.NewLinkKey()
	if err != nil {
		return err
	}
	keys, err := otcrypto.Derive(linkKey, os.Getenv("ONETIME_SECRET"))
	if err != nil {
		return err
	}
	payload, err := otcrypto.Encrypt(keys, msg)
	if err != nil {
		return err
	}
	base := strings.TrimRight(*server, "/")
	var res saveSecretResponse
	if err := postJSON(base+"/api/saveSecret", saveSecretRequest{
		SecretMessage: payload, HashedKey: keys.Token, Duration: *days * 86400,
	}, &res); err != nil {
		return err
	}
	if res.Status != "ok" {
		return fmt.Errorf("server: %s", res.Status)
	}
	fmt.Fprintf(stdout, "%s/v/#%s\n", base, otcrypto.Fragment(linkKey, res.NewID))
	return nil
}

func clientRead(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: 1time read LINK")
	}
	link := args[0]
	linkKey, id, err := otcrypto.ParseFragment(link)
	if err != nil {
		return errors.New("not a v2 link (old links open only in the browser)")
	}
	base := link
	if i := strings.Index(base, "/v/"); i >= 0 {
		base = base[:i]
	} else {
		return errors.New("link must contain /v/")
	}
	keys, err := otcrypto.Derive(linkKey, os.Getenv("ONETIME_SECRET"))
	if err != nil {
		return err
	}
	var res getResponse
	if err := postJSON(base+"/api/get", getRequest{ID: id, HashedKey: keys.Token}, &res); err != nil {
		return err
	}
	switch res.Status {
	case "ok":
	case "wrong key":
		return errors.New("wrong or missing secret key (set ONETIME_SECRET)")
	case "no message":
		return errors.New("message was destroyed or never existed")
	default:
		return fmt.Errorf("server: %s", res.Status)
	}
	plain, err := otcrypto.Decrypt(keys, res.CryptedMessage)
	if err != nil {
		return err
	}
	_, err = stdout.Write(plain)
	return err
}
