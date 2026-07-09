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

// Package discovery answers "is this CRD installed on the cluster?" for
// optional integrations (Prometheus Operator ServiceMonitors, OpenShift
// Routes). Shared by the monitoring and route phases (B4) and the
// operator's own metrics ServiceMonitor (F4).
package discovery

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// HasGVK reports whether the cluster's RESTMapper can resolve the given
// GroupVersionKind — i.e. whether the backing CRD (or built-in type) is
// installed. The manager's mapper is dynamic, so CRDs installed after
// operator start are picked up on subsequent reconciles without a restart.
func HasGVK(mapper meta.RESTMapper, gvk schema.GroupVersionKind) bool {
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}
