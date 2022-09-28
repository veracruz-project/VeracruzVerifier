package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dreemkiller/VeracruzVerifier/session"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/moogar0880/problems"
	"github.com/veraison/services/config"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/vtsclient"
)

func reportProblem(c *gin.Context, status int, details ...string) {
	fmt.Printf("Problem: %v\n", details)
	prob := problems.NewStatusProblem(status)

	if len(details) > 0 {
		prob.Detail = strings.Join(details, ", ")
	}

	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, prob)
}

const (
	ChallengeResponseSessionMediaType = "application/vnd.veraison.challenge-response-session+json"
	tenantID                          = "0"
)

var (
	caCert x509.Certificate
	//caPrivateKey ecdsa.PrivateKey
	caPrivateKey crypto.Signer
)

type ProxyHandler struct {
	sessionManager *session.SessionManager
	vtsClient      vtsclient.IVTSClient
}

func NewProxyHandler(session_manager *session.SessionManager, vtsClient vtsclient.IVTSClient) *ProxyHandler {
	handler := ProxyHandler{
		sessionManager: session_manager,
		vtsClient:      vtsClient,
	}
	return &handler
}

func (o *ProxyHandler) Start(c *gin.Context) {
	// we do not care about the contents of the message we receive.
	id, err := o.sessionManager.CreateSession()
	if err != nil {
		reportProblem(c, http.StatusInternalServerError, fmt.Sprintf("Failed to create session:%v\n", err))
		return
	}

	session, err := o.sessionManager.GetSession(id)
	if err != nil {
		reportProblem(c, http.StatusInternalServerError, fmt.Sprintf("I seriously have no idea what's going on here:%v\n", err))
		return
	}

	c.Header("Location", id.String())
	c.Data(http.StatusCreated, ChallengeResponseSessionMediaType, session.Nonce)
	return
}

func extractIdEvidence(c *gin.Context) (*uuid.UUID, []byte, error) {
	uriPathSegment := c.Param("id")
	id, err := uuid.Parse(uriPathSegment)
	if err != nil {
		return nil, nil, fmt.Errorf("extractIdEvidence uuid.Parse failed:%v", err)
	}

	// read body (i.e., evidence)
	evidence, err := io.ReadAll(c.Request.Body)
	if err != nil || len(evidence) == 0 {
		return nil, nil, fmt.Errorf("esxtractIdEvidence io.ReadAll failed:%v", err)
	}
	return &id, evidence, nil

}
func (o *ProxyHandler) PsaRouter(c *gin.Context) { // What data do we need? device id, attestation token, public key.
	_, _, err := extractIdEvidence(c)
	if err != nil {
		reportProblem(c,
			http.StatusBadRequest,
			fmt.Sprintf("PsaRouter: extractIdEvidence failed:%v", err))
		return
	}

	return
}
func (o *ProxyHandler) NitroRouter(c *gin.Context) { // What data do we need? device id, attestation document
	mediaType := c.Request.Header.Get("Content-Type")
	id, evidence, err := extractIdEvidence(c)
	if err != nil {
		reportProblem(c,
			http.StatusBadRequest,
			fmt.Sprintf("NitroRouter: extractIdEvidence failed:%v", err))
		return
	}

	token := &proto.AttestationToken{
		TenantId:  tenantID,
		Data:      evidence,
		MediaType: mediaType,
	}

	appraisalCtx, err := o.vtsClient.GetAttestation(
		context.Background(),
		token,
	)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: o.vtsClient.GetAttestation failed:%v", err))
		return
	}

	if appraisalCtx.Result.TrustVector.HardwareAuthenticity != proto.AR_Status_SUCCESS {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: appraisalCtx.Result.TrustVector.HardwareAuthenticity:%v is not \"SUCCESS\"", appraisalCtx.Result.TrustVector.HardwareAuthenticity))
		return
	}
	evidenceMap := appraisalCtx.Result.ProcessedEvidence.AsMap()

	nonce, err := base64.StdEncoding.DecodeString(evidenceMap["nonce"].(string))
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: appraisalCtx.Result.ProcessedEvidence[\"nonce\"]:%v could not be decoded as base64:%v", evidenceMap["nonce"], err))
		return
	}
	session, err := o.sessionManager.GetSession(id)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: Unable to find session for id:%v, err:%v", id, err))
		return
	}
	if !bytes.Equal(session.Nonce, nonce) {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: Received nonce:%v did not match stored challenge:%v", nonce, session.Nonce))
		return
	}

	pcr0, err := base64.StdEncoding.DecodeString(evidenceMap["PCR0"].(string))
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: appraisalCtx.Result.ProcessedEvidence[\"PCR0\"]:%v could not be decoded as base64:%v", evidenceMap["PCR0"], err))
		return
	}
	csr_data, err := base64.StdEncoding.DecodeString(evidenceMap["user_data"].(string))
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: appraisalCtx.Result.ProcessedEvidence[\"user_data\"]:%v could not be decoded as base64:%v", evidenceMap["user_data"], err))
		return
	}
	csr, err := x509.ParseCertificateRequest(csr_data)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("nitroRouter: failed to convert received PEM:%v into CSR:%v", csr_data, err))
		return
	}
	err = csr.CheckSignature()
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: CSR signature is invalid:%v", err))
		return
	}

	clientCert, err := convertCSRIntoCert(csr, pcr0[0:32])
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("NitroRouter: convertCSRIntoCert failed:%v", err))
		return
	}

	certData := append(clientCert[:], caCert.Raw[:]...)

	c.Data(http.StatusOK, ChallengeResponseSessionMediaType, certData)
	return
}

var VERACRUZ_RUNTIME_HASH_EXTENSION_ID = []int{2, 5, 30, 1}

func convertCSRIntoCert(csr *x509.CertificateRequest, enclave_hash []byte) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24) // currently sets expiry to a day from now TODO Make this configurable
	serialNumber := big.NewInt(23)

	enclave_hash_hex := make([]byte, hex.EncodedLen(len(enclave_hash)))
	hex.Encode(enclave_hash_hex, enclave_hash)
	obj_id := asn1.ObjectIdentifier{VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3]}
	veracruzExtension := pkix.Extension{
		Id:       obj_id,
		Critical: false,
		Value:    enclave_hash_hex,
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

	clientCertTemplate := x509.Certificate{
		Version:               2,
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtraExtensions:       []pkix.Extension{veracruzExtension},
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLenZero:        false,
		MaxPathLen:            0,
		PublicKey:             csr.PublicKey,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
	}

	clientCert, err := x509.CreateCertificate(rand.Reader, &clientCertTemplate, &caCert, csr.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("convertCSRIntoCert: Failed to generate certificate:%v", err)
	}
	return clientCert, nil
}

func loadCaCert() error {
	filename := "./CACert.pem"
	pem_data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("os.ReadFile failed to open %v for reading:%v", filename, err)
	}
	block, _ := pem.Decode(pem_data)
	if block == nil {
		return fmt.Errorf("pem.Decode failed on file:%v", filename)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParseCertificate failed:%v", err)
	}
	caCert = *cert
	return nil
}

func loadCaKey() error {
	filename := "./CAKey.pem"
	pem_data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("os.ReadFile failed to open %v for reading:%v", filename, err)
	}
	block, _ := pem.Decode(pem_data)
	if block == nil {
		return fmt.Errorf("pem.Decode failed on file:%v", filename)
	}

	tempPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParseECPrivateKey failed:%v", err)
	}
	caPrivateKey = tempPrivateKey
	return nil
}

func main() {
	fmt.Println("Hello, World!")

	err := loadCaCert()
	if err != nil {
		fmt.Printf("loadCaCert failed:%v\n", err)
		return
	}

	err = loadCaKey()
	if err != nil {
		fmt.Printf("loadCaKey failed:%v\n", err)
		return
	}

	var listenAddress string

	flag.StringVar(&listenAddress, "l", "", "Address to listen on")
	flag.Parse()

	session_manager := session.NewSessionManager()

	vtsClientCfg := config.Store{
		"vts-server.addr": "vts:50051",
	}
	vtsClient := vtsclient.NewGRPC(vtsClientCfg)

	proxyHandler := NewProxyHandler(session_manager, vtsClient)

	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.Group("/proxy/v1").
		POST("/Start", proxyHandler.Start).
		POST("PSA/:psa_request", proxyHandler.PsaRouter).
		POST("Nitro/:id", proxyHandler.NitroRouter)

	err = router.Run()
	if err != nil {
		fmt.Println("Router failed to run")
	}
}
