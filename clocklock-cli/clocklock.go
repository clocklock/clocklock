package main

import (
	"bufio"
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/clocklock/clocklock"
	"github.com/clocklock/go-rfc3161"
	"github.com/codegangsta/cli"
	"github.com/phayes/cryptoid"
)

var regexNumber = regexp.MustCompile("^\\d+$")
var regexOid = regexp.MustCompile("([0-9]+\\.)*[0-9]+")

func main() {
	app := cli.NewApp()
	app.Name = "clocklock"
	app.Usage = "secure timestamping from a Time Stamp Authority (TSA) via a Time Stamp Protocol"
	app.Commands = []cli.Command{
		{
			Name:   "rfc3161",
			Usage:  "Stamp a hash using the RFC-3161 Time-Stamp Protocol",
			Action: rfc3161Action,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url",
					Usage: "url endpoint for the time stamp authority. For example https://bouder.clocklock.net/boulder-ordered-256",
				},
				cli.StringFlag{
					Name:  "hash",
					Value: "SHA256",
					Usage: "hash algorithm for digest. SHA256 is assumed if not provided",
				},
				cli.StringFlag{
					Name:  "nonce",
					Usage: "provide a numeric nonce to be used for the request. If not provided, a nonce will be generated. Use --nonce=none to omit it entirely",
				},
				cli.BoolFlag{
					Name:  "no-verify",
					Usage: "skip verification. This can be useful when high throughput is needed and verification will happen later",
				},
				cli.BoolFlag{
					Name:  "no-cert",
					Usage: "Do not request the certificate. --no-verify must also be passed. ",
				},
				cli.StringFlag{
					Name:  "policy",
					Usage: "Request a specific stamping policy. Specify by OID (`1.2.345.67.8.9`)",
				},
			},
		},
		{
			Name:   "stamp",
			Usage:  "Stamp a hash using the ClockLock Time-Stamp Protocol",
			Action: stampAction,
		},
		{
			Name:   "hashes",
			Usage:  "List all available hashes",
			Action: hashesAction,
		},
	}
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "url",
			Usage: "url endpoint for the time stamp authority. For example https://bouder.clocklock.net/boulder-ordered-256",
		},
		cli.StringFlag{
			Name:  "hash",
			Value: "SHA256",
			Usage: "hash algorithm for digest. SHA256 is assumed if not provided",
		},
		cli.StringFlag{
			Name:  "nonce",
			Usage: "provide a numeric nonce to be used for the request. If not provided, a nonce will be generated. Use --nonce=none to omit it entirely",
		},
		cli.BoolFlag{
			Name:  "no-verify",
			Usage: "skip verification. This can be useful when high throughput is needed and verification will happen later",
		},
		cli.StringFlag{
			Name:  "policy",
			Usage: "Request a specific stamping policy. May be the policy identifer (`boulder-ordered-256`), or the OID (`1.2.345.67.8.9`)",
		},
	}
	app.Run(os.Args)

}

func rfc3161Action(c *cli.Context) {
	if c.String("url") == "" {
		log.Fatal("--url is required")
	}

	if c.NArg() > 0 {
		for _, arg := range c.Args() {
			resp, err := rfc3161request(arg, c)
			if err != nil && resp == nil {
				log.Fatal(err)
			}
			out, err := asn1.Marshal(resp)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Print(out)
		}
	} else {
		stdin := bufio.NewReader(os.Stdin)
		scanner := bufio.NewScanner(stdin)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			resp, err := rfc3161request(scanner.Text(), c)
			if err != nil && resp == nil {
				log.Fatal(err)
			}
			out, err := asn1.Marshal(resp)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Print(out)
		}
	}
}

func rfc3161request(digest string, c *cli.Context) (*rfc3161.TimeStampResp, error) {
	// Get the Hash
	hash, err := cryptoid.HashAlgorithmByName(c.String("hash"))
	if err != nil {
		log.Fatal("Unable to find hash algorithm by that name. Run `clocklock hashes` to see a list of available algorithms.")
	}

	// Get the bytes
	dbytes, err := hex.DecodeString(digest)
	if err != nil {
		return nil, err
	}
	if hash.Hash.Size() != len(dbytes) {
		return nil, errors.New("Provided hash digest is incorrect length. Try specifying a different hash algorithm.")
	}

	// Build the request
	request, err := rfc3161.NewTimeStampReq(hash.Hash, dbytes)
	if err != nil {
		return nil, err
	}

	// Set the nonce
	if c.String("nonce") == "" {
		err = request.GenerateNonce()
		if err != nil {
			return nil, err
		}
	} else if regexNumber.MatchString(c.String("nonce")) {
		_, ok := request.Nonce.SetString(c.String("nonce"), 10)
		if !ok {
			return nil, errors.New("Failed to set specified nonce")
		}
	} else if c.String("nonce") != "none" {
		return nil, errors.New("Unable to understand nonce. Nonce must be numeric")
	}

	// Set the policy
	if c.String("policy") != "" {
		if !regexOid.MatchString(c.String("policy")) {
			return nil, errors.New("Invalid policy OID. OID must be of the form 1.23.45.678")
		}
		parts := strings.Split(c.String("policy"), ".")
		oid := make([]int, len(parts))
		for i, part := range parts {
			oid[i], err = strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("Invalid policy OID. OID must be of the form 1.23.45.678")
			}
		}
		request.ReqPolicy = asn1.ObjectIdentifier(oid)
	}

	// Set Certificate Request
	if c.Bool("no-cert") {
		if !c.Bool("no-verify") {
			return nil, errors.New("May not pass --no-cert without also passing --no-verify")
		}
	} else {
		request.CertReq = true
	}

	// Do the request
	client := rfc3161.NewClient(c.String("url"))
	resp, err := client.Do(request)
	if err != nil {
		return resp, err
	}

	// Verify as needed
	if !c.Bool("no-verify") {
		err = resp.Verify(request, nil)
		if err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func stampAction(c *cli.Context) {
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

func hashesAction(c *cli.Context) {
	fmt.Println(`MD5
SHA1
SHA224
SHA256
SHA384
SHA512
SHA3-224
SHA3-256
SHA3-384
SHA3-512`)
}
