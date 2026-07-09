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

package tls

import "time"

// Shared TTL constants for the per-NomadCluster certificate tree. Do
// not introduce purpose-specific TTL constants without a documented
// reason.
const (
	// CALifetime is the validity duration of the operator-generated CA
	// (C5 / AC-2.4.8): capped at 2 years so a compromised or leaked CA
	// key has a bounded blast radius, at the cost of a documented
	// renewal obligation (status.certificateAuthority.renewalRequiredBy).
	CALifetime = 2 * 365 * 24 * time.Hour

	// ServerCertTTL is the validity duration of issued leaf certificates.
	ServerCertTTL = 365 * 24 * time.Hour

	// CertWarningWindow is the window before expiry at which a certificate is
	// considered due for renewal. ValidateCertificate returns an error inside
	// this window so the calling reconciler reissues the cert.
	CertWarningWindow = 30 * 24 * time.Hour
)
