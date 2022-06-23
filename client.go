package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func fileExists(path string) bool {
	_, error := os.Stat(path)
	return !errors.Is(error, os.ErrNotExist)
}

func generatePrivateKey(path string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Unable to generate private key: %s", err)
		os.Exit(1)
	}
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(path)
	privatePem.Chmod(0600)
	if err != nil {
		fmt.Printf("Unable to create %s: %s\n", path, err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("Unable to encode the private key %s\n", err)
		os.Exit(1)
	}
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}

func generateCertificateSigningRequest(keyPath string, deviceId string) (err error, csr string) {
	subj := pkix.Name{
		CommonName: deviceId,
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Unable to read key file: %s\n", err)
		os.Exit(1)
	}

	keyPem, _ := pem.Decode(keyBytes)
	keyDecoded, err := parsePrivateKey(keyPem.Bytes)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyDecoded)
	if err != nil {
		return err, ""
	}

	writer := new(strings.Builder)
	pem.Encode(writer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return nil, writer.String()
}

func sign(message string, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func buildMessage(method string, path string, version string, createdAt string, expiry string, body string) string {
	message := []string{method, path, version, createdAt, expiry}
	if method == "POST" {
		message = append(message, body)
	}
	return strings.Join(message, "\n")
}

func requestCertificate(csr string, server string, deviceId string, secretKey string, ca *string) (string, error) {
	t := time.Now().UTC()

	var client *http.Client
	if ca != nil {
		caCert, err := ioutil.ReadFile(*ca)
		if err != nil {
			return "", err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client = &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: true,
				},
			},
		}
	} else {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	method := "POST"
	path := "/certificates/request"
	version := "1.0"
	createdAt := t.Format(time.RFC3339)
	expiry := t.Add(time.Minute * 15).Format(time.RFC3339)
	message := buildMessage(method, path, version, createdAt, expiry, csr)
	signature := sign(message, secretKey)

	req, err := http.NewRequest(method, server+path, strings.NewReader(csr))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Hmac key-id="+deviceId+", signature=\""+signature+"\"")
	req.Header.Add("Created-at", createdAt)
	req.Header.Add("Expiry", expiry)
	req.Header.Add("X-Firmware-Version", version)
	req.Header.Add("Content-type", "text/plain")

	response, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", errors.New("Error: " + fmt.Sprint(response.StatusCode))
	}

	body, err := ioutil.ReadAll(response.Body)
	return string(body), err
}

func checkCertificateValidity(certificatePath string) (bool, error) {
	certBytes, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		return false, err
	}

	certPem, _ := pem.Decode(certBytes)

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	// Certificate is invalid if it is due to expire is less than 7 days time
	return cert.NotAfter.Before(now.Add(time.Hour * 24 * -7)), nil
}

func main() {
	var server string
	var ca string
	var deviceId string
	var secretKey string
	var certificatePath string
	var privateKey string

	flag.StringVar(&server, "server", "", "Providore server adddress")
	flag.StringVar(&ca, "ca", "", "Providore Server Certificate Authority Certificate")
	flag.StringVar(&deviceId, "device-id", "", "Client device id")
	flag.StringVar(&secretKey, "secret-key", "", "Client secret key")
	flag.StringVar(&certificatePath, "cert-path", "", "Path to the certificate to monitor")
	flag.StringVar(&privateKey, "cert-key", "", "Path to the private key")
	flag.Parse()

	if !fileExists(privateKey) {
		fmt.Println("Private key not found. Generating one.")
		generatePrivateKey(privateKey)
	}

	if !fileExists(certificatePath) {
		fmt.Println("Certificate not found. Requesting a new one.")
		err, csr := generateCertificateSigningRequest(privateKey, deviceId)
		if err != nil {
			fmt.Printf("Unable to generate a CSR: %s\n", err.Error())
			os.Exit(1)
		}

		// Next! Request the Certificate!
		certificate, err := requestCertificate(csr, server, deviceId, secretKey, &ca)
		if err != nil {
			fmt.Printf("Unable to request a certificate: %s\n", err.Error())
			os.Exit(1)
		}
		err = ioutil.WriteFile(certificatePath, []byte(certificate), 0600)
		if err != nil {
			fmt.Printf("Unable to write a certificate: %s\n", err.Error())
			os.Exit(1)
		}

		fmt.Printf("New Certificate created!\n")
		os.Exit(0)
	}

	valid, err := checkCertificateValidity(certificatePath)
	if err != nil {
		fmt.Printf("Unable to check the validity of the certificate: %s\n", err.Error())
		os.Exit(1)
	}

	if valid {
		err, csr := generateCertificateSigningRequest(privateKey, deviceId)
		if err != nil {
			fmt.Printf("Unable to generate a CSR: %s\n", err.Error())
			os.Exit(1)
		}

		certificate, err := requestCertificate(csr, server, deviceId, secretKey, &ca)
		if err != nil {
			fmt.Printf("Unable to request a certificate: %s\n", err.Error())
			os.Exit(1)
		}

		err = ioutil.WriteFile(certificatePath, []byte(certificate), 0600)
		if err != nil {
			fmt.Printf("Unable to write a certificate: %s\n", err.Error())
			os.Exit(1)
		}

		fmt.Printf("New Certificate generated!\n")
		os.Exit(0)
	} else {
		fmt.Print("Certificate does not need renewing\n")
	}
}
