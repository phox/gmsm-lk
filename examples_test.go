package lk_test

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/phox/gmsm-lk"
)

type MyLicence struct {
	Email string    `json:"email"`
	End   time.Time `json:"end"`
}

// Example_complete creates a new license and validate it.
func Example_complete() {
	// create a new Private key:
	privateKey, err := lk.NewPrivateKey()
	if err != nil {
		log.Fatal("private key generation failed: " + err.Error())

	}

	// create a license document:
	doc := MyLicence{
		"test@example.com",
		time.Now().Add(time.Hour * 24 * 365), // 1 year
	}

	// marshall the document to json bytes:
	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)

	}

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal("license generation failed: " + err.Error())

	}

	// encode the new license to b64, this is what you give to your customer.
	str64, err := license.ToB64String()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(str64)

	// get the public key. The public key should be hardcoded in your app
	// to check licences. Do not distribute the private key!
	publicKey := privateKey.GetPublicKey()

	// validate the license:
	if ok, err := license.Verify(publicKey); err != nil {
		log.Fatal("license verification failed: " + err.Error())
	} else if !ok {
		log.Fatal("Invalid license signature")
	}

	// unmarshal the document and check the end date:
	res := MyLicence{}
	if err := json.Unmarshal(license.Data, &res); err != nil {
		log.Fatal(err)
	} else if res.End.Before(time.Now()) {
		log.Fatalf("License expired on: %s", res.End.String())
	} else {
		fmt.Printf(`Licensed to %s until %s \n`, res.Email, res.End.Format("2006-01-02"))
	}
}

// Example_licenseGeneration shows how to create a license file from a private
// key using SM2 algorithm.
func Example_licenseGeneration() {
	// Generate a new SM2 private key dynamically for this example
	privateKey, err := lk.NewPrivateKey()
	if err != nil {
		log.Fatal("private key generation failed: " + err.Error())
	}

	// Here we use a struct that is marshalled to json,
	// but ultimatly all you need is a []byte.
	doc := struct {
		Email string    `json:"email"`
		End   time.Time `json:"end"`
	}{
		"test@example.com",
		time.Now().Add(time.Hour * 24 * 365), // 1 year
	}

	// marshall the document to []bytes (this is the data that our license
	// will contain):
	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)
	}

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal("license generation failed: " + err.Error())
	}

	// the b32 representation of our license, this is what you give to
	// your customer.
	licenseB32, err := license.ToB32String()
	if err != nil {
		log.Fatal("license encoding failed: " + err.Error())

	}

	// print the license that you should give to your customer
	fmt.Println(licenseB32)
}

// Example_licenseVerification validates a previously generated license with
// a public key using SM2 algorithm.
func Example_licenseVerification() {
	// Generate a new SM2 private key for this example
	privateKey, err := lk.NewPrivateKey()
	if err != nil {
		log.Fatal("private key generation failed: " + err.Error())
	}

	// Create license data
	doc := struct {
		Email string    `json:"email"`
		End   time.Time `json:"end"`
	}{
		"test@example.com",
		time.Now().Add(time.Hour * 24 * 365),
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)
	}

	// Generate license
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal("license generation failed: " + err.Error())
	}

	// Get the license as B32 string (simulating what a customer would receive)
	licenseB32, err := license.ToB32String()
	if err != nil {
		log.Fatal("license encoding failed: " + err.Error())
	}

	// Get the public key (this should be hardcoded in your app)
	publicKey := privateKey.GetPublicKey()
	publicKeyB32 := publicKey.ToB32String()

	// Now simulate the verification process that would happen in your app

	// Unmarshal the public key from B32
	parsedPublicKey, err := lk.PublicKeyFromB32String(publicKeyB32)
	if err != nil {
		log.Fatal("public key unmarshal failed: " + err.Error())
	}

	// Unmarshal the customer license from B32
	parsedLicense, err := lk.LicenseFromB32String(licenseB32)
	if err != nil {
		log.Fatal("license unmarshal failed: " + err.Error())
	}

	// validate the license signature:
	if ok, err := parsedLicense.Verify(parsedPublicKey); err != nil {
		log.Fatal("license verification failed: " + err.Error())
	} else if !ok {
		log.Fatal("Invalid license signature")
	}

	result := struct {
		Email string    `json:"email"`
		End   time.Time `json:"end"`
	}{}

	// unmarshal the document:
	if err := json.Unmarshal(parsedLicense.Data, &result); err != nil {
		log.Fatal(err)
	}

	// Now you just have to check the end date and if it before time.Now(),
	// then you can continue!
	// if result.End.Before(time.Now()) {
	// 	log.Fatal("License expired on: %s", result.End.Format("2006-01-02"))
	// } else {
	// 	fmt.Printf(`Licensed to %s until %s`, result.Email, result.End.Format("2006-01-02"))
	// }
}
