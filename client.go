package main

import (
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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
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

func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

func generateCertificateSigningRequest(keyPath string, deviceId string, configuration map[string]string) (err error, csr string) {
	subj := pkix.Name{
		CommonName: deviceId,
	}
	if value, ok := configuration["country"]; ok {
		subj.Country = []string{value}
	}
	if value, ok := configuration["state-or-province"]; ok {
		subj.Province = []string{value}
	}
	if value, ok := configuration["locality"]; ok {
		subj.Locality = []string{value}
	}
	if value, ok := configuration["street-address"]; ok {
		subj.StreetAddress = []string{value}
	}
	if value, ok := configuration["postal-code"]; ok {
		subj.PostalCode = []string{value}
	}
	if value, ok := configuration["organization"]; ok {
		subj.Organization = []string{value}
	}
	if value, ok := configuration["organizational-unit"]; ok {
		subj.OrganizationalUnit = []string{value}
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
					InsecureSkipVerify: viper.GetBool("insecure"),
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
	configFilePath := flag.StringP("config", "c", "", "Path to config file")
	version := flag.BoolP("version", "v", false, "Print the version number")
	help := flag.BoolP("help", "h", false, "Print this help message")

	flag.String("server", "", "Providore server address")
	flag.String("ca", "", "Providore Server Certificate Authority Certificate")
	flag.String("device-id", "", "Client device id")
	flag.String("secret", "", "Client secret token")
	flag.String("cert-path", "", "Path to the certificate to monitor")
	flag.Bool("insecure", false, "Don't validate the certificate against the CA")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Println("0.0.1")
		os.Exit(0)
	}

	if *configFilePath != "" {
		viper.SetConfigFile(*configFilePath)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/providore-client/")
		viper.AddConfigPath("$HOME/.config/providore-client/")
	}
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		_, ok := err.(viper.ConfigFileNotFoundError)

		if !ok {
			fmt.Println("Unable to read config file: %s", err)
		}
	}

	viper.BindPFlags(flag.CommandLine)

	server := viper.GetString("server")
	ca := viper.GetString("ca")
	deviceId := viper.GetString("device-id")
	secret := viper.GetString("secret")
	certificatePath := viper.GetString("cert-path")
	privateKeyPath := viper.GetString("key-path")
	csrConfiguration := viper.GetStringMapString("csr")

	if server == "" {
		fmt.Println("Providore server URL not set!\n")
		flag.Usage()
		os.Exit(1)
	}

	if deviceId == "" {
		fmt.Println("Device ID not set!\n")
		flag.Usage()
		os.Exit(1)
	}

	if secret == "" {
		fmt.Println("Secret Key not set!\n")
		flag.Usage()
		os.Exit(1)
	}

	if certificatePath == "" {
		fmt.Println("Certificate Path not set!\n")
		flag.Usage()
		os.Exit(1)
	}

	if privateKeyPath == "" {
		fmt.Println("Private Key Path not set!\n")
		flag.Usage()
		os.Exit(1)
	}

	if !fileExists(privateKeyPath) {
		fmt.Println("Private key not found. Generating one.")
		generatePrivateKey(privateKeyPath)
	}

	if !fileExists(certificatePath) {
		fmt.Println("Certificate not found. Requesting a new one.")
		err, csr := generateCertificateSigningRequest(privateKeyPath, deviceId, csrConfiguration)
		if err != nil {
			fmt.Printf("Unable to generate a CSR: %s\n", err.Error())
			os.Exit(1)
		}

		// Next! Request the Certificate!
		certificate, err := requestCertificate(csr, server, deviceId, secret, &ca)
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
		err, csr := generateCertificateSigningRequest(privateKeyPath, deviceId, csrConfiguration)
		if err != nil {
			fmt.Printf("Unable to generate a CSR: %s\n", err.Error())
			os.Exit(1)
		}

		certificate, err := requestCertificate(csr, server, deviceId, secret, &ca)
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
