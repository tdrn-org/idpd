/*
 * Copyright 2025-2026 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package forward

import (
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/scheme"
)

const Name scheme.Name = "forward"

type Handler struct {
	runtime scheme.Runtime
}

func NewHandler(runtime scheme.Runtime) *Handler {
	return &Handler{
		runtime: runtime,
	}
}

func (h *Handler) Name() scheme.Name {
	return Name
}

func (h *Handler) Mount(instance *httpserver.Instance) {
}
