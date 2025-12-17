/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package phases

import (
	"testing"
)

func TestConfigChecksum_Deterministic(t *testing.T) {
	// Create the same data multiple times and verify checksum is consistent
	data := map[string]string{
		"zebra":    "last",
		"apple":    "first",
		"middle":   "center",
		"acl":      "true",
		"tls":      "false",
		"replicas": "3",
	}

	// Calculate checksum multiple times
	checksums := make([]string, 100)
	for i := 0; i < 100; i++ {
		checksums[i] = ConfigChecksum(data)
	}

	// All checksums should be identical
	first := checksums[0]
	for i, checksum := range checksums {
		if checksum != first {
			t.Errorf("Checksum at iteration %d differs: got %s, want %s", i, checksum, first)
		}
	}
}

func TestConfigChecksum_DifferentData(t *testing.T) {
	data1 := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	data2 := map[string]string{
		"key1": "value1",
		"key2": "different",
	}

	checksum1 := ConfigChecksum(data1)
	checksum2 := ConfigChecksum(data2)

	if checksum1 == checksum2 {
		t.Error("Different data should produce different checksums")
	}
}

func TestConfigChecksum_EmptyData(t *testing.T) {
	data := map[string]string{}
	checksum := ConfigChecksum(data)

	if checksum == "" {
		t.Error("Empty data should still produce a checksum")
	}

	// Verify it's deterministic even when empty
	checksum2 := ConfigChecksum(data)
	if checksum != checksum2 {
		t.Errorf("Empty data checksum not deterministic: got %s and %s", checksum, checksum2)
	}
}
