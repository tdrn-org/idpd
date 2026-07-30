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

package domain

import (
	"context"
	"net/netip"

	"golang.org/x/text/language"
)

type AuditLogEntry struct {
	ID string
	AuditLogInfo
}

type AuditLogInfo struct {
	Address netip.Addr
	Host    string
	Lat     float64
	Lng     float64
	City    map[language.Tag]string
	Country map[language.Tag]string
}

type AuditLog interface {
	LookupAuditLogInfo(ctx context.Context) (*AuditLogInfo, error)
	RecordAuditLogEntry(ctx context.Context) (*AuditLogEntry, error)
	GetAuditLogEntry(ctx context.Context, id string) (*AuditLogEntry, error)
}
