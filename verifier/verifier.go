// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package verifier

import (
	"errors"
	"fmt"
	"github.com/veraison/services/verification/verifier"
)
type Verifier struct {

}

func (v Verifier) IsSupportedMediaType(mt string) bool {
	return false
}

func (v Verifier) SupportedMediaTypes() []string {
	var types []string
	return types
}

func (v Verifier) ProcessEvidence(tenantID string, data []byte, mt string) ([]byte, error) {
	return nil, errors.New("poop")
}

func NewVerifier() (verifier.IVerifier, error) {
	fmt.Println("veracruz_verifier/verifier/NewVerifier started")

	v := Verifier {}

	fmt.Println("veracruz_verifier/verifier/NewVerifier finished.")
	return v, nil
}
