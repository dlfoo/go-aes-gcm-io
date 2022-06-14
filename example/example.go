// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Example usage of the writer/reader.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	gcm "github.com/dlfoo/aesgcmio"
)

func main() {
	// Declare the key we will use to encrypt the plaintext.
	key, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		log.Fatal(err)
	}

	// Create a buffer of 1096 bytes.
	plaintext := make([]byte, 1096)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Plaintext: %x\n", plaintext)
	fmt.Printf("Plaintext Size: %d bytes\n", len(plaintext))

	plaintextReader := bytes.NewBuffer(plaintext)

	cipherTextWriter := new(bytes.Buffer)

	// Create new GCM writer to encrypt ciphertext buffer. Setting 0 means
	// default chunk size will be used.
	w, err := gcm.NewWriter(cipherTextWriter, key, 0)
	if err != nil {
		log.Fatal(err)
	}

	// Write the plaintext bytes to the cipherTextWriter.
	_, err = io.Copy(w, plaintextReader)
	if err != nil {
		log.Fatal(err)
	}

	// Be sure to explicitly close the writer to flush any remaining data.
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %x\n", cipherTextWriter.Bytes())
	fmt.Printf("Ciphertext Size: %d bytes\n", cipherTextWriter.Len())

	// Create new reader to decrypt ciphertext.
	r, err := gcm.NewReader(cipherTextWriter, key)
	if err != nil {
		log.Fatal(err)
	}

	plaintextWriter := new(bytes.Buffer)

	// Read the decrypted plaintext from the reader.
	_, err = io.Copy(plaintextWriter, r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %x\n", plaintextWriter.Bytes())
	fmt.Printf("Decrypted Size: %d bytes\n", plaintextWriter.Len())
	fmt.Printf("Equal: %t\n", bytes.Equal(plaintext, plaintextWriter.Bytes()))
}
