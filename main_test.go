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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
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
