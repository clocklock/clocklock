package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"github.com/clocklock/clocklock"
	"log"
	"os"
)

func main() {
	rule, err := clocklock.FetchRule("http://localhost:8080", "boulder-ordered-256")
	if err != nil {
		log.Fatal(err)
	}

	cli := clocklock.NewClient(rule)
	err = cli.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer cli.GracefulClose()

	encoder := json.NewEncoder(os.Stdout)
	stdin := bufio.NewReader(os.Stdin)
	scanner := bufio.NewScanner(stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		digest, err := hex.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}

		req := clocklock.NewRequest(rule.Id, crypto.SHA256, digest)
		req.GenerateNonce()

		resp, err := cli.SendReceive(req)
		if err != nil {
			log.Fatal(err)
		}
		err = encoder.Encode(resp)
		if err != nil {
			log.Fatal(err)
		}
	}
}
