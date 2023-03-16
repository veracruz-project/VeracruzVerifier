//! Proxy Attestation Server for the Veracruz project
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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/moogar0880/problems"
	"github.com/spf13/viper"
	"github.com/veracruz-project/proxy_attestation_server/session"
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
	caCert       x509.Certificate
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

func extractIdTokenCsr(c *gin.Context) (*uuid.UUID, []byte, []byte, error) {
	uriPathSegment := c.Param("id")
	id, err := uuid.Parse(uriPathSegment)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr uuid.Parse failed:%v", err)
	}
	form, err := c.MultipartForm()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr: MultipartForm failed:%v", err)
	}
	doc, ok := form.Value["token"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr: \"doc\" entry not found in form")
	}
	doc_bytes, err := base64.StdEncoding.DecodeString(doc[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr: Decode of doc failed:%v", err)
	}
	csr, ok := form.Value["csr"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr: \"csr\" entry not found in form")
	}

	csr_bytes, err := base64.StdEncoding.DecodeString(csr[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extractIdDocCsr: Decode of csr failed:%v", err)
	}
	return &id, doc_bytes, csr_bytes, nil

}

func parseAttestationResultPsa(ctx *proto.AppraisalContext) (*[]byte, *[]byte, *[]byte, error) {
	evidence_map := (*ctx.Evidence.Evidence).AsMap()

	nonce_entry := evidence_map["psa-nonce"]
	if nonce_entry == nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: no nonce entry in evidence map")
	}
	nonce_string, ok := nonce_entry.(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: nonce_entry:%v cannot be interpreted as a string", nonce_entry)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonce_string)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: result.Nonce:%v could not be decoded as base64:%v", nonce_string, err)
	}

	psa_sw_components := evidence_map["psa-software-components"]
	if psa_sw_components == nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: no psa-software-components entry in evidence map")
	}

	component_array, ok := psa_sw_components.([]interface{})
	if !ok {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: Failed to interpret psa_sw_components:%v as array of interface{}", psa_sw_components)
	}

	var runtime_manager_hash []byte
	var csr_hash []byte
	found_arot := false
	for _, this_component := range component_array {
		this_component_map, ok := this_component.(map[string]interface{})
		if !ok {
			return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: this_component:%v cannot be interpreted as a map[string]interface{}", this_component)
		}
		fmt.Printf("this_component_map:%v\n", this_component_map)
		measurement_type, ok := this_component_map["measurement-type"].(string)
		if !ok {
			return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: this_component_map[\"measurement-type\"]:%v cannot be interpreted as a string", this_component_map["measurement-type"])
		}
		if measurement_type == "ARoT" {
			found_arot = true
			measurement_value, ok := this_component_map["measurement-value"].(string)
			if !ok {
				return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: this_component_map[\"measurement-value\"]:%v cannot be interpreted as a string", this_component_map["measurement-value"])
			}

			runtime_manager_hash, err = base64.StdEncoding.DecodeString(measurement_value)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: %v could not be decoded as base64:%v", measurement_value, err)
			}

			signer_id, ok := this_component_map["signer-id"].(string)
			if !ok {
				return nil, nil, nil, fmt.Errorf("parseAttestationResultPsa: this_component_map[\"signer-id\"]:%v cannot be interpreted as a string", this_component_map["signer-id"])
			}

			csr_hash, err = base64.StdEncoding.DecodeString(signer_id)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("PsaRouter: %v could not be decoded as base64:%v", signer_id, err)
			}
			break
		}
	}
	if !found_arot {
		return nil, nil, nil, fmt.Errorf("PSARouter: Failed to find ARoT measurement in PSA token")
	}

	
	return &nonce, &runtime_manager_hash, &csr_hash, nil
}

func parseAttestationResultNitro(ctx *proto.AppraisalContext) (*[]byte, *[]byte, *[]byte, error) {
	evidence_map := (*ctx.Evidence.Evidence).AsMap()

	nonce_entry := evidence_map["nonce"]
	if nonce_entry == nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: no nonce entry in evidence map")
	}
	nonce_string, ok := evidence_map["nonce"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: nonce_entry:%v cannot be interpreted as a string", nonce_entry)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonce_string)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: nonce_string:%v could not be decoded as base64:%v", nonce_string, err)
	}

	pcr0 := evidence_map["PCR0"]
	if pcr0 == nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: No PCR0 entry in evidence_map")
	}
	pcr0_string, ok := pcr0.(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: pcr0:%v could not be interpreted as a string", pcr0)
	}
	runtime_manager_hash, err := base64.StdEncoding.DecodeString(pcr0_string)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: pcr0_string:%v could not be decoded as base64:%v", pcr0_string, err)
	}
	// AWS NItro used SHA384. We only use the first 32 bytes
	runtime_manager_hash = runtime_manager_hash[0:32]

	user_data := evidence_map["user_data"]
	if user_data == nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: No user_data entry in evidence_map")
	}
	user_data_string, ok := user_data.(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: user_data:%v could not be interpreted as a string", user_data)
	}
	csr_hash, err := base64.StdEncoding.DecodeString(user_data_string)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parseAttestationResultNitro: user_data_string:%v could not be decoded as base64:%v", user_data_string, err)
	}

	return &nonce, &runtime_manager_hash, &csr_hash, nil
}

type PlatformType uint8

const (
	PSAPlatform   PlatformType = 0
	NitroPlatform              = 1
)

func (o *ProxyHandler) genericRouter(c *gin.Context, platform PlatformType) {
	id, tokenData, csr_data, err := extractIdTokenCsr(c)
	if err != nil {
		reportProblem(c,
			http.StatusBadRequest,
			fmt.Sprintf("genericRouter: extractIdEvidence failed:%v", err))
		return
	}

	var mediaType string
	if platform == PSAPlatform {
		mediaType = "application/psa-attestation-token"
	} else if platform == NitroPlatform {
		mediaType = "application/aws-nitro-document"
	} else {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: unsupported `platform` value(%v) received", platform))
		return
	}

	token := &proto.AttestationToken{
		TenantId:  tenantID,
		Data:      tokenData,
		MediaType: mediaType,
	}

	appraisalCtx, err := o.vtsClient.GetAttestation(
		context.Background(),
		token,
	)
	if err != nil {
		fmt.Printf("GetAttestation failed:%v\n", err)
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: o.vtsClient.GetAttestation failed:%v", err))
		return
	}

	var nonce *[]byte
	var runtime_manager_hash *[]byte
	var received_csr_hash *[]byte
	if platform == PSAPlatform {
		nonce, runtime_manager_hash, received_csr_hash, err = parseAttestationResultPsa(appraisalCtx)
		if err != nil {
			reportProblem(c,
				http.StatusInternalServerError,
				fmt.Sprintf("genericRouter: Call to parseAttestationResultPsa failed:%v", err))
			return
		}
	} else if platform == NitroPlatform {
		nonce, runtime_manager_hash, received_csr_hash, err = parseAttestationResultNitro(appraisalCtx)
		if err != nil {
			reportProblem(c,
				http.StatusInternalServerError,
				fmt.Sprintf("genericRouter: Call to parseAttestationResultNitro failed:%v", err))
			return
		}
	} else {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: Unsupported platform (%v) received", platform))
		return
	}

	session, err := o.sessionManager.GetSession(id)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: Unable to find session for id:%v, err:%v", id, err))
		return
	}
	if !bytes.Equal(session.Nonce, *nonce) {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: Received nonce:%v did not match stored challenge:%v", nonce, session.Nonce))
		return
	}

	h := sha256.New()
	h.Write(csr_data)
	calculated_csr_hash := h.Sum(nil)

	if !bytes.Equal(*received_csr_hash, calculated_csr_hash) {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: received CSR hash (%v) does not match calculated CSR hash(%v)", received_csr_hash, calculated_csr_hash))
	}

	csr, err := x509.ParseCertificateRequest(csr_data)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: failed to convert received PEM:%v into CSR:%v", csr_data, err))
		return
	}

	err = csr.CheckSignature()
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: CSR signature is invalid:%v", err))
		return
	}

	clientCert, err := convertCSRIntoCert(csr, *runtime_manager_hash)
	if err != nil {
		reportProblem(c,
			http.StatusInternalServerError,
			fmt.Sprintf("genericRouter: convertCSRIntoCert failed:%v", err))
		return
	}

	certData := append(clientCert[:], caCert.Raw[:]...)

	c.Data(http.StatusOK, ChallengeResponseSessionMediaType, certData)
	return
}

func (o *ProxyHandler) PsaRouter(c *gin.Context) {
	o.genericRouter(c, PSAPlatform)
	return
}

func (o *ProxyHandler) NitroRouter(c *gin.Context) {
	o.genericRouter(c, NitroPlatform)
	return
}

var VERACRUZ_RUNTIME_HASH_EXTENSION_ID = []int{2, 5, 30, 1}

func convertCSRIntoCert(csr *x509.CertificateRequest, enclave_hash []byte) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24) // currently sets expiry to a day from now TODO Make this configurable
	serialNumber := big.NewInt(23)

	obj_id := asn1.ObjectIdentifier{VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2], VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3]}
	veracruzExtension := pkix.Extension{
		Id:       obj_id,
		Critical: false,
		Value:    enclave_hash,
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
		return nil, fmt.Errorf("x.509.CreateCertificate failed::%w", err)
	}
	return clientCert, nil
}

func loadCaCert(filename string) error {
	pem_data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("os.ReadFile failed to open %v for reading:%w", filename, err)
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

func loadCaKey(filename string) error {
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

func createRouter(proxyHandler *ProxyHandler) (*gin.Engine, error) {
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.Group("/proxy/v1").
		POST("/Start", proxyHandler.Start).
		POST("PSA/:id", proxyHandler.PsaRouter).
		POST("Nitro/:id", proxyHandler.NitroRouter)
	return router, nil
}

func main() {
	fmt.Println("Starting Proxy Attestation Server")

	err := loadCaCert("./CACert.pem")
	if err != nil {
		fmt.Printf("Proxy Attestation Server: loadCaCert failed:%v\n", err)
		return
	}

	err = loadCaKey("./CAKey.pem")
	if err != nil {
		fmt.Printf("Proxy Attestation Server: loadCaKey failed:%v\n", err)
		return
	}

	var listenAddress string

	flag.StringVar(&listenAddress, "l", "127.0.0.1:3030", "Address to listen on")
	flag.Parse()

	session_manager := session.NewSessionManager()

	vtsClientCfg := viper.New()
	vtsClientCfg.SetDefault("server-addr", "127.0.0.1:50051")
	vtsClient := vtsclient.NewGRPC()
	if err = vtsClient.Init(vtsClientCfg); err != nil {
		fmt.Printf("vtsClient.Init failed:%v\n", err)
		return
	}

	proxyHandler := NewProxyHandler(session_manager, vtsClient)

	router, err := createRouter(proxyHandler)
	if err != nil {
		fmt.Printf("Failed to create router:%v\n", err)
		return
	}

	err = router.Run(listenAddress)
	if err != nil {
		fmt.Printf("Proxy Attestation Server: Router failed to run:%v\n", err)
	}
}
