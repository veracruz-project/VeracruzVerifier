//! tests for the Proxy Attestation Server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	nitro_enclave_attestation_document "github.com/veracruz-project/go-nitro-enclave-attestation-document"
	"github.com/veracruz-project/proxy_attestation_server/session"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/services/vtsclient"
)

func Test_loadCa(t *testing.T) {
	err := loadCaCert()
	if err != nil {
		t.Fatalf("loadCaCert failed:%v\n", err)
	}
	err = loadCaKey()
	if err != nil {
		t.Fatalf("loadCaKey failed:%v\n", err)
	}
}

func Test_CSR(t *testing.T) {
	csrPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var name = pkix.Name{}
	var csrTemplate = x509.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, csrPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest failed:%v\n", err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed:%v\n", err)
	}

	enclave_hash := make([]byte, 32)
	rand.Read(enclave_hash)
	generatedCert, err := convertCSRIntoCert(csr, enclave_hash)
	if err != nil {
		t.Fatalf("convertCSRIntoCert failed:%v\n", err)
	}

	parsedGeneratedCert, err := x509.ParseCertificate(generatedCert)
	if err != nil {
		t.Fatalf("ParseCertificate failed:%v\n", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(&caCert)

	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Roots:     roots,
	}

	_, err = parsedGeneratedCert.Verify(opts)
	if err != nil {
		t.Fatalf("Verify failed:%v\n", err)
	}
}

func Test_Start(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	proxyHandler := createTestProxyHandler()

	router, err := createRouter(proxyHandler)
	if err != nil {
		t.Fatalf("Failed to create router:%v\n", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/proxy/v1/Start", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	header := w.Header()
	assert.Equal(t, header.Get("Content-Type"), string("application/vnd.veraison.challenge-response-session+json"))
	// Make sure there is a reeturned Location in the header
	location := header.Get("Location")
	// Make sure the location decodes correctly to a UUID
	_, err = uuid.FromString(location)
	assert.NoError(t, err)
	// Make sure the nonce received in the Body is the right length?
	nonceBytes := w.Body.Bytes()
	assert.Equal(t, 32, len(nonceBytes))
}

func Test_Nitro(t *testing.T) {
	endKey, endCertDer, _, caCertDer, err := generateCertsAndKeys(false, false)
	if err != nil {
		t.Fatalf("Failed to generateCertsAndKeys:%v\n", err)
	}

	// start the vts service
	vtsCtx, cancel_vts_service := context.WithCancel(context.Background())
	defer cancel_vts_service()
	go startAndMonitorProcess(vtsCtx, "./vts", "vts")
	// start the provisioning service
	provisioningCtx, cancel_provisioning_service := context.WithCancel(context.Background())
	defer cancel_provisioning_service()

	if err = startProvisioningService(provisioningCtx); err != nil {
		t.Fatalf("Failed to start the provisioning service")
	}

	proxyHandler := createTestProxyHandler()

	// provision the fake AWS credentials to the services
	if err := provision_nitro_corim(caCertDer); err != nil {
		t.Fatalf("Failed to provision nitro credentials:%v\n", err)
	}

	router, err := createRouter(proxyHandler)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/proxy/v1/Start", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	header := w.Header()
	assert.Equal(t, header.Get("Content-Type"), string("application/vnd.veraison.challenge-response-session+json"))
	// Make sure there is a reeturned Location in the header
	location := header.Get("Location")
	// Make sure the location decodes correctly to a UUID
	session_id, err := uuid.FromString(location)
	assert.NoError(t, err)
	// Make sure the nonce received in the Body is the right length?
	nonceBytes := w.Body.Bytes()

	csr, err := generateCSR()
	if err != nil {
		t.Fatalf("Failed to generate CSR:%v\n", err)
	}
	h := sha256.New()
	h.Write(csr)
	csrHash := h.Sum(nil)

	PCRs, err := generatePCRs()
	document, err := nitro_enclave_attestation_document.GenerateDocument(PCRs, csrHash, nonceBytes, endCertDer, [][]byte{caCertDer}, endKey)

	if err != nil {
		t.Fatalf("Failed to generate PCRs:%v\n", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	tokenField, err := writer.CreateFormField("token")
	if err != nil {
		t.Fatalf("Failed to create token field:%v\n", err)
	}
	encodedDocument := base64.StdEncoding.EncodeToString(document)
	_, err = io.Copy(tokenField, strings.NewReader(encodedDocument))
	if err != nil {
		t.Fatalf("Failed to copy document base64:%v\n", err)
	}
	csrField, err := writer.CreateFormField("csr")
	if err != nil {
		t.Fatalf("Failed to create CSR field:%v\n", err)
	}
	encodedCSR := base64.StdEncoding.EncodeToString(csr)
	_, err = io.Copy(csrField, strings.NewReader(encodedCSR))
	if err != nil {
		t.Fatalf("Failed to copy CSR field:%v\n", err)
	}

	writer.Close()

	nitro_url := fmt.Sprintf("/proxy/v1/Nitro/%v", session_id)
	nitroReq := httptest.NewRequest(http.MethodPost, nitro_url, bytes.NewReader(body.Bytes()))
	nitroReq.Header.Set("Content-Type", writer.FormDataContentType())

	w = httptest.NewRecorder()
	router.ServeHTTP(w, nitroReq)
	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_PSA(t *testing.T) {
	// 	endKey, endCertDer, caCertDer, err := generateCertsAndKeys(false, false)
	// 	if err != nil {
	// 		t.Fatalf("Failed to generateCertsAndKeys:%v\n", err)
	// 	}

	// start the vts service
	vtsCtx, cancel_vts_service := context.WithCancel(context.Background())
	defer cancel_vts_service()
	go startAndMonitorProcess(vtsCtx, "./vts", "vts")
	// start the provisioning service
	provisioningCtx, cancel_provisioning_service := context.WithCancel(context.Background())
	defer cancel_provisioning_service()

	if err := startProvisioningService(provisioningCtx); err != nil {
		t.Fatalf("Failed to start the provisioning service")
	}

	// 	proxyHandler := createTestProxyHandler()

	// 	// provision the fake PSA credentials to the services
	// 	if err := provision_psa_corim(); err != nil {
	// 		t.Fatalf("Failed to provision nitro credentials:%v\n", err)
	// 	}

	// 	router, err := createRouter(proxyHandler)
	// 	assert.NoError(t, err)

	// 	req := httptest.NewRequest(http.MethodPost, "/proxy/v1/Start", nil)
	// 	w := httptest.NewRecorder()
	// 	router.ServeHTTP(w, req)
	// 	assert.Equal(t, http.StatusCreated, w.Code)
	// 	header := w.Header()
	// 	assert.Equal(t, header.Get("Content-Type"), string("application/vnd.veraison.challenge-response-session+json"))
	// 	// Make sure there is a reeturned Location in the header
	// 	location := header.Get("Location")
	// 	// Make sure the location decodes correctly to a UUID
	// 	session_id, err := uuid.FromString(location)
	// 	assert.NoError(t, err)
	// 	// Make sure the nonce received in the Body is the right length?
	// 	nonceBytes := w.Body.Bytes()

	// 	csr, err := generateCSR()
	// 	if err != nil {
	// 		t.Fatalf("Failed to generate CSR:%v\n", err)
	// 	}
	// 	h := sha256.New()
	// 	h.Write(csr)
	// 	csrHash := h.Sum(nil)

	// 	document, err := nitro_enclave_attestation_document.GenerateDocument(PCRs, csrHash, nonceBytes, endCertDer, [][]byte{caCertDer}, endKey)

	// 	if err != nil {
	// 		t.Fatalf("Failed to generate PCRs:%v\n", err)
	// 	}

	// 	body := &bytes.Buffer{}
	// 	writer := multipart.NewWriter(body)
	// 	tokenField, err := writer.CreateFormField("token")
	// 	if err != nil {
	// 		t.Fatalf("Failed to create token field:%v\n", err)
	// 	}
	// 	encodedDocument := base64.StdEncoding.EncodeToString(document)
	// 	_, err = io.Copy(tokenField, strings.NewReader(encodedDocument))
	// 	if err != nil {
	// 		t.Fatalf("Failed to copy document base64:%v\n", err)
	// 	}
	// 	csrField, err := writer.CreateFormField("csr")
	// 	if err != nil {
	// 		t.Fatalf("Failed to create CSR field:%v\n", err)
	// 	}
	// 	encodedCSR := base64.StdEncoding.EncodeToString(csr)
	// 	_, err = io.Copy(csrField, strings.NewReader(encodedCSR))
	// 	if err != nil {
	// 		t.Fatalf("Failed to copy CSR field:%v\n", err)
	// 	}

	// 	writer.Close()

	// 	nitro_url := fmt.Sprintf("/proxy/v1/Nitro/%v", session_id)
	// 	nitroReq := httptest.NewRequest(http.MethodPost, nitro_url, bytes.NewReader(body.Bytes()))
	// 	nitroReq.Header.Set("Content-Type", writer.FormDataContentType())

	// 	w = httptest.NewRecorder()
	// 	router.ServeHTTP(w, nitroReq)
	// 	assert.Equal(t, http.StatusOK, w.Code)
}

func createTestProxyHandler() *ProxyHandler {
	vtsAddress := "127.0.0.1:50051"

	session_manager := session.NewSessionManager()

	vtsClientCfg := viper.New()
	vtsClientCfg.SetDefault("server-addr", vtsAddress)
	vtsClient := vtsclient.NewGRPC()
	vtsClient.Init(vtsClientCfg)

	proxyHandler := NewProxyHandler(session_manager, vtsClient)
	return proxyHandler
}

func startProvisioningService(ctx context.Context) error {
	go startAndMonitorProcess(ctx, "./provisioning", "provisioning")

	// wait for the provisioning service to come up
	numIterations := 0
	for {
		_, err := http.Get("http://127.0.0.1:8888/goober")
		if err == nil {
			// the server is up
			break
		}
		numIterations++
		if numIterations > 50 {
			return fmt.Errorf("Provisioning service startup timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func startAndMonitorProcess(ctx context.Context, executable string, dir string) error {
	cmd := exec.CommandContext(ctx, executable)
	cmd.Dir = dir
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("StderrPipe failed:%v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdoutPipe failed:%v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Start failed:%v", err)
	}

	go func() {
		stderrScanner := bufio.NewScanner(stderr)
		stderrScanner.Split(bufio.ScanLines)
		for stderrScanner.Scan() {
			m := stderrScanner.Text()
			fmt.Printf("%v\n", m)
		}
	}()
	go func() {
		stdoutScanner := bufio.NewScanner(stdout)
		stdoutScanner.Split(bufio.ScanLines)
		for stdoutScanner.Scan() {
			m := stdoutScanner.Text()
			fmt.Printf("%v\n", m)
		}
	}()
	return nil
}

func provision_nitro_corim(caCertDer []byte) error {
	// first, generate the COMID
	templateBytes, err := ioutil.ReadFile("AWSNitroComidTemplate.json")
	if err != nil {
		return fmt.Errorf("Failed to read template file:%w", err)
	}
	template := string(templateBytes)
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDer,
	}
	caCertPem := string(pem.EncodeToMemory(&block))
	caCertPem = strings.Replace(caCertPem, "\n", "\\n", -1)
	awsNitroComidJSON := strings.Replace(template, "<CERTIFICATE>", caCertPem, 1)
	var myComid comid.Comid
	myComid.FromJSON([]byte(awsNitroComidJSON))

	if err = myComid.Valid(); err != nil {
		return fmt.Errorf("myComid is invalid:%w\n", err)
	}

	corimCBOR, err := generateCORIM(myComid)
	if err != nil {
		return fmt.Errorf("generateCORIM failed:%w", err)
	}

	cborReader := bytes.NewReader(corimCBOR)
	url := "http://127.0.0.1:8888/endorsement-provisioning/v1/submit"
	request, err := http.NewRequest("POST", url, cborReader)
	request.Header.Add("CONTENT-TYPE", "application/corim-unsigned+cbor; profile=http://aws.com/nitro")
	client := http.Client{
		Timeout: time.Second * 10,
	}
	_, err = client.Do(request)
	if err != nil {
		return fmt.Errorf("client.Do failed:%w", err)
	}
	return nil
}

func provision_psa_corim() error {
	// first, generate the COMID
	psaComidJSON, err := ioutil.ReadFile("MyComidPsaIak.json")
	if err != nil {
		return fmt.Errorf("Failed to read template file:%w", err)
	}
	var myComid comid.Comid
	myComid.FromJSON([]byte(psaComidJSON))

	if err = myComid.Valid(); err != nil {
		return fmt.Errorf("myComid is invalid:%w\n", err)
	}

	// Next, generate the CORIM
	corimCBOR, err := generateCORIM(myComid)
	if err != nil {
		return fmt.Errorf("generateCORIM failed:%w", err)
	}

	cborReader := bytes.NewReader(corimCBOR)
	url := "http://127.0.0.1:8888/endorsement-provisioning/v1/submit"
	request, err := http.NewRequest("POST", url, cborReader)
	request.Header.Add("CONTENT-TYPE", "application/corim-unsigned+cbor; profile=http://aws.com/nitro")
	client := http.Client{
		Timeout: time.Second * 10,
	}
	_, err = client.Do(request)
	if err != nil {
		return fmt.Errorf("client.Do failed:%w", err)
	}
	return nil
}

func generateCORIM(myComid comid.Comid) ([]byte, error) {
	corimTemplateBytes, err := ioutil.ReadFile("corimMini.json")
	if err != nil {
		return nil, fmt.Errorf("Failed to read corimMini file:%w", err)
	}
	var myCorim corim.UnsignedCorim
	if err = myCorim.FromJSON(corimTemplateBytes); err != nil {
		return nil, fmt.Errorf("Failed to create myCorim:%w", err)
	}
	if myCorim.AddComid(myComid) == nil {
		return nil, fmt.Errorf("Failed to add COMID to CORIM")
	}
	if err = myCorim.Valid(); err != nil {
		return nil, fmt.Errorf("myCorim is invalid:%w", err)
	}
	corimCBOR, err := myCorim.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("myCorim.ToCBOR failed:%w", err)
	}
	return corimCBOR, nil
}

func generateCertsAndKeys(endCertExpired bool, caCertExpired bool) (*ecdsa.PrivateKey, []byte, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate CA key:%v", err)
	}

	caNotBefore, caNotAfter := generateValidTimeRange(caCertExpired)
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: caNotBefore,
		NotAfter:  caNotAfter,

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDer, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate CA Certificate:%v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDer)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to convert CA Cert der to certificate:%v", err)
	}

	endKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate end key:%v", err)
	}

	endNotBefore, endNotAfter := generateValidTimeRange(endCertExpired)
	endTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: endNotBefore,
		NotAfter:  endNotAfter,

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	endCertDer, err := x509.CreateCertificate(rand.Reader, &endTemplate, caCert, &endKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate end certificate:%v", err)
	}
	return endKey, endCertDer, caCert, caCertDer, nil
}

func generateValidTimeRange(expired bool) (time.Time, time.Time) {
	var notBefore time.Time
	var notAfter time.Time
	if expired {
		notBefore = time.Now().Add(-time.Hour * 24)
		notAfter = time.Now().Add(-time.Hour * 1)
	} else {
		notBefore = time.Now()
		notAfter = time.Now().Add(time.Hour * 24 * 180)
	}
	return notBefore, notAfter
}

func generateCSR() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate key:%v", err)
	}
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Spacely Sprockets"},
			OrganizationalUnit: []string{"Widget production"},
			Locality:           []string{"Orbit City"},
			Province:           []string{"Orbit State"},
			StreetAddress:      []string{"Skypad Apartments"},
			PostalCode:         []string{"Out there"},
			CommonName:         "George",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate certificate request:%v\n", err)
	}
	return csr, nil
}

func generateRandomSlice(size int32) []byte {
	result := make([]byte, size)
	rand.Read(result)
	return result
}

const NUM_PCRS = 16

func generatePCRs() (map[int32][]byte, error) {
	pcrs := make(map[int32][]byte)
	for i := int32(0); i < NUM_PCRS; i++ {
		pcrs[i] = generateRandomSlice(96)
	}
	return pcrs, nil
}
