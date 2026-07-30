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

package model

import (
	"context"
	_ "embed"
	"fmt"
	"net/netip"

	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/tdrn-org/idpd/internal/i18n"
)

type AuditLogEntry struct {
	ID      string
	Address string
	Host    string
	Lat     float64
	Lng     float64
	City    i18n.Name
	Country i18n.Name
}

func (e *AuditLogEntry) ToDomain() (*domain.AuditLogEntry, error) {
	if e == nil {
		return nil, nil
	}
	address, err := netip.ParseAddr(e.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP address '%s' (cause: %w)", e.Address, err)
	}
	auditLogEntry := &domain.AuditLogEntry{
		ID: e.ID,
		AuditLogInfo: domain.AuditLogInfo{
			Address: address,
			Host:    e.Host,
			Lat:     e.Lat,
			Lng:     e.Lng,
			City:    e.City,
			Country: e.Country,
		},
	}
	return auditLogEntry, nil
}

//go:embed audit_log_entry.insert.sql
var insertAuditLogEntrySQL string

func InsertAuditLogEntry(ctx context.Context, tx *database.Tx, auditLogEntry *domain.AuditLogEntry) (*AuditLogEntry, error) {
	e := &AuditLogEntry{
		ID:      database.NewID(),
		Address: auditLogEntry.Address.StringExpanded(),
		Host:    auditLogEntry.Host,
		Lat:     auditLogEntry.Lat,
		Lng:     auditLogEntry.Lng,
		City:    i18n.Name(auditLogEntry.City),
		Country: i18n.Name(auditLogEntry.Country),
	}
	err := tx.ExecTx(ctx, insertAuditLogEntrySQL,
		e.ID,
		e.Address,
		e.Host,
		e.Lat,
		e.Lng,
		e.City,
		e.Country,
	)
	if err != nil {
		return nil, err
	}
	auditLogEntry.ID = e.ID
	return e, nil
}

//go:embed audit_log_entry.select_by_id.sql
var selectAuditLogEntryByIDSQL string

func SelectAuditLogEntryByID(ctx context.Context, tx *database.Tx, id string) (*AuditLogEntry, error) {
	row, err := tx.QueryRowTx(ctx, selectAuditLogEntryByIDSQL, id)
	if err != nil {
		return nil, err
	}
	e := &AuditLogEntry{
		ID: id,
	}
	err = database.ScanRow(row, e, "address", "host", "lat", "lng", "city", "country")
	if database.NoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return e, nil
}
