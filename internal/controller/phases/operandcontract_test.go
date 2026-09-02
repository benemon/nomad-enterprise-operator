//go:build operandcontract

package phases

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
)

// Operand-contract gate (neo-ce6): every server.hcl shape the operator
// can render must be accepted by the pinned operand image's own config
// loader. Catches renamed or misspelled stanzas that HCL would
// otherwise reject only at operand boot. Requires docker and the
// OPERAND_IMAGE env var; runs in the operand-contract CI job, not the
// unit lane.

func operandImage(t *testing.T) string {
	t.Helper()
	img := os.Getenv("OPERAND_IMAGE")
	if img == "" {
		t.Fatal("OPERAND_IMAGE not set (e.g. hashicorp/nomad:2.0.5-ent)")
	}
	return img
}

func validateServerHCL(t *testing.T, img, name, config string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.hcl")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "run", "--rm",
		"-v", dir+":/cfg:ro", img, "config", "validate", "/cfg/server.hcl").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Configuration is valid!") {
		t.Errorf("%s: operand rejected rendered server.hcl (err=%v):\n%s\n--- config:\n%s", name, err, out, config)
	}
}

func contractCluster() *nomadv1alpha1.NomadCluster {
	cluster := newTestCluster("contract-ns", "contract")
	cluster.Spec.Replicas = 3
	return cluster
}

// keyringVariants mirrors entryBlock's provider arms: one fully
// populated CRD entry per provider, rendered through the same
// entryBlock + Generator path production uses.
func keyringVariants() map[string]nomadv1alpha1.KeyringEntry {
	return map[string]nomadv1alpha1.KeyringEntry{
		"awskms": {Name: "aws", AWSKMS: &nomadv1alpha1.AWSKMSKeyring{
			KMSKeyID: "alias/stub", Region: "eu-west-2", Endpoint: "https://kms.example:4566",
		}},
		"azurekeyvault": {Name: "azure", AzureKeyVault: &nomadv1alpha1.AzureKeyVaultKeyring{
			VaultName: "stub-vault", KeyName: "stub-key", TenantID: "stub-tenant",
			Environment: "AZUREPUBLICCLOUD", Resource: "vault.azure.net",
		}},
		"gcpckms": {Name: "gcp", GCPCKMS: &nomadv1alpha1.GCPCKMSKeyring{
			Project: "stub", Region: "europe-west2", KeyRing: "ring", CryptoKey: "key",
		}},
		"transit": {Name: "vault1", Transit: &nomadv1alpha1.TransitKeyring{
			Address: "https://vault.example:8200", KeyName: "nomad-root",
			MountPath: "transit/", Namespace: "admin", KeyIDPrefix: "a-",
		}},
	}
}

func TestOperandContract_ServerHCL(t *testing.T) {
	img := operandImage(t)

	render := func(t *testing.T, cluster *nomadv1alpha1.NomadCluster, keyrings []hcl.KeyringBlock) string {
		t.Helper()
		gen := hcl.NewGenerator(cluster, "203.0.113.10", "c2VjcmV0LWdvc3NpcC1rZXk=")
		gen.Keyrings = keyrings
		config, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return config
	}

	t.Run("baseline", func(t *testing.T) {
		validateServerHCL(t, img, "baseline", render(t, contractCluster(), nil))
	})

	for typ, entry := range keyringVariants() {
		t.Run("keyring-"+typ, func(t *testing.T) {
			block := entryBlock(storedKeyring{Entry: &entry}, true)
			if block.Type != typ {
				t.Fatalf("entryBlock rendered type %q, want %q", block.Type, typ)
			}
			if typ == "transit" {
				block.Args = append(block.Args, hcl.KeyringArg{Key: "token", Value: "stub-token"})
			}
			validateServerHCL(t, img, typ, render(t, contractCluster(),
				[]hcl.KeyringBlock{block, {Type: "aead", Active: false}}))
		})
	}

	t.Run("vaults", func(t *testing.T) {
		cluster := contractCluster()
		cluster.Spec.Server.Vaults = []nomadv1alpha1.VaultEntry{{
			Name: "default",
			DefaultIdentity: &nomadv1alpha1.VaultDefaultIdentity{
				Audiences: []string{"vault.io"},
				TTL:       "1h",
			},
		}}
		validateServerHCL(t, img, "vaults", render(t, cluster, nil))
	})

	// Canary: a misspelled stanza must FAIL validation, proving the
	// oracle still parses strictly rather than silently ignoring.
	t.Run("oracle-canary", func(t *testing.T) {
		config := render(t, contractCluster(), nil) + "\nkeyering \"transit\" {\n  active = true\n}\n"
		dir := t.TempDir()
		path := filepath.Join(dir, "server.hcl")
		if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("docker", "run", "--rm",
			"-v", dir+":/cfg:ro", img, "config", "validate", "/cfg/server.hcl").CombinedOutput()
		if err == nil {
			t.Errorf("oracle accepted a config with an unknown stanza:\n%s", out)
		}
	})
}
