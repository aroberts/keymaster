// Command fakephone stands in for the phone in keymaster's tests. It does
// what the approval page and an iCloud passkey do: fetch a request from the
// relay, sign SHA-256 of its bytes as a WebAuthn assertion (or create a new
// ES256 credential), and post the result. It uses Go's crypto, so the tests
// check keymaster's Swift verifier against an independent implementation.
//
// -tamper breaks one part of the response, to check keymaster rejects it.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
)

type keyFile struct {
	CredentialID string `json:"credentialId"`
	PrivateKey   []byte `json:"privateKey"`
}

var b64 = base64.RawURLEncoding

func main() {
	relay := flag.String("relay", "", "relay base URL")
	id := flag.String("id", "", "request id")
	keyPath := flag.String("key", "", "key file, written by enroll and read by assert")
	mode := flag.String("mode", "assert", "enroll, assert or deny")
	origin := flag.String("origin", "", "origin to claim (default: the relay URL's origin)")
	tamper := flag.String("tamper", "", "challenge, origin, rpid, uv, up, type, signature or credential")
	flag.Parse()

	base, err := url.Parse(*relay)
	if err != nil {
		log.Fatal(err)
	}
	if *origin == "" {
		*origin = base.Scheme + "://" + base.Host
	}
	api := *relay + "/api/requests/" + *id

	if *mode == "deny" {
		post(api+"/deny", map[string]any{})
		return
	}

	res, err := http.Get(api)
	if err != nil {
		log.Fatal(err)
	}
	var got struct{ Request string }
	json.NewDecoder(res.Body).Decode(&got)
	res.Body.Close()
	raw, err := b64.DecodeString(got.Request)
	if err != nil {
		log.Fatalf("bad request from relay: %v", err)
	}
	challenge := sha256.Sum256(raw)
	if *tamper == "challenge" {
		challenge[0] ^= 0xff
	}
	rpID := base.Hostname()
	if *tamper == "rpid" {
		rpID = "evil.example"
	}
	ceremony := "webauthn.get"
	if *mode == "enroll" {
		ceremony = "webauthn.create"
	}
	if *tamper == "type" {
		ceremony = "payment.get"
	}
	claimedOrigin := *origin
	if *tamper == "origin" {
		claimedOrigin = "https://evil.example"
	}
	clientData, _ := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   b64.EncodeToString(challenge[:]),
		"origin":      claimedOrigin,
		"crossOrigin": false,
	})
	rpHash := sha256.Sum256([]byte(rpID))
	flags := byte(0x05)
	if *tamper == "uv" {
		flags = 0x01
	}
	if *tamper == "up" {
		flags = 0x04
	}

	switch *mode {
	case "enroll":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		credID := make([]byte, 16)
		rand.Read(credID)
		spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		var auth bytes.Buffer
		auth.Write(rpHash[:])
		auth.WriteByte(flags | 0x40)
		auth.Write([]byte{0, 0, 0, 0})
		auth.Write(make([]byte, 16))
		binary.Write(&auth, binary.BigEndian, uint16(len(credID)))
		auth.Write(credID)
		auth.Write([]byte{0xa0}) // stands in for the COSE key, which keymaster doesn't read
		pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
		data, _ := json.Marshal(keyFile{CredentialID: b64.EncodeToString(credID), PrivateKey: pkcs8})
		if err := os.WriteFile(*keyPath, data, 0o600); err != nil {
			log.Fatal(err)
		}
		reported := credID
		if *tamper == "credential" {
			reported = []byte("not the attested id")
		}
		post(api+"/response", map[string]any{
			"type":               "credential",
			"credentialId":       b64.EncodeToString(reported),
			"publicKey":          b64.EncodeToString(spki),
			"publicKeyAlgorithm": -7,
			"authenticatorData":  b64.EncodeToString(auth.Bytes()),
			"clientDataJSON":     b64.EncodeToString(clientData),
		})
	case "assert":
		data, err := os.ReadFile(*keyPath)
		if err != nil {
			log.Fatal(err)
		}
		var kf keyFile
		json.Unmarshal(data, &kf)
		parsed, err := x509.ParsePKCS8PrivateKey(kf.PrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		key := parsed.(*ecdsa.PrivateKey)
		auth := append(append(rpHash[:], flags), 0, 0, 0, 0)
		clientHash := sha256.Sum256(clientData)
		digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
		sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if *tamper == "signature" {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			sig, _ = ecdsa.SignASN1(rand.Reader, other, digest[:])
		}
		credID := kf.CredentialID
		if *tamper == "credential" {
			credID = b64.EncodeToString([]byte("unknown credential"))
		}
		post(api+"/response", map[string]any{
			"type":              "assertion",
			"credentialId":      credID,
			"authenticatorData": b64.EncodeToString(auth),
			"clientDataJSON":    b64.EncodeToString(clientData),
			"signature":         b64.EncodeToString(sig),
		})
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

func post(url string, body any) {
	data, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		fmt.Fprintln(os.Stderr, "relay answered", res.Status)
		os.Exit(1)
	}
}
