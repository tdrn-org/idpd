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

package audit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/tdrn-org/go-cache"
	"github.com/tdrn-org/go-cache/memory"
	"github.com/tdrn-org/go-database"
	"github.com/tdrn-org/go-httpserver"
	"github.com/tdrn-org/idpd/internal/audit/model"
	"github.com/tdrn-org/idpd/internal/data"
	"github.com/tdrn-org/idpd/internal/domain"
	"github.com/tdrn-org/idpd/internal/geoip"
)

type Runtime interface {
	DataStore() *data.Store
}

type Log struct {
	runtime       Runtime
	geoipProvider geoip.Provider
	entryCache    cache.KeyValue[netip.Addr, *domain.AuditLogInfo]
}

const entryCacheTTL time.Duration = time.Hour

func NewLog(runtime Runtime, geoipProvider geoip.Provider) (*Log, error) {
	l := &Log{
		runtime:       runtime,
		geoipProvider: geoipProvider,
	}
	entryCache, err := memory.NewKeyValue(0, -entryCacheTTL, l.loadAuditInfo)
	if err != nil {
		return nil, err
	}
	l.entryCache = entryCache
	return l, nil
}

func (l *Log) loadAuditInfo(ctx context.Context, address netip.Addr) (*domain.AuditLogInfo, error) {
	host := address.String()
	hosts, err := net.DefaultResolver.LookupAddr(ctx, host)
	if err == nil && len(hosts) > 0 {
		host = hosts[0]
	}
	geoipInfo, err := l.geoipProvider.Lookup(ctx, address)
	if err != nil {
		return nil, err
	}
	auditLogInfo := &domain.AuditLogInfo{
		Address: address,
		Host:    host,
		Lat:     geoipInfo.Lat,
		Lng:     geoipInfo.Lng,
		City:    geoipInfo.City,
		Country: geoipInfo.Country,
	}
	return auditLogInfo, nil
}

func (l *Log) LookupAuditLogInfo(ctx context.Context) (*domain.AuditLogInfo, error) {
	address, ok := httpserver.RemoteIP(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to determine Remote IP")
	}
	return l.entryCache.Get(ctx, address)
}

func (l *Log) RecordAuditLogEntry(ctx context.Context) (*domain.AuditLogEntry, error) {
	auditLogInfo, err := l.LookupAuditLogInfo(ctx)
	if err != nil {
		return nil, err
	}
	auditLogEntry := &domain.AuditLogEntry{
		AuditLogInfo: *auditLogInfo,
	}
	err = l.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		_, err := model.InsertAuditLogEntry(txCtx, tx, auditLogEntry)
		return err
	})
	if err != nil {
		return nil, err
	}
	return auditLogEntry, nil
}

func (l *Log) GetAuditLogEntry(ctx context.Context, id string) (*domain.AuditLogEntry, error) {
	var auditLogEntry *domain.AuditLogEntry
	err := l.runtime.DataStore().Atomic(ctx, func(txCtx context.Context, tx *database.Tx) error {
		e, err := model.SelectAuditLogEntryByID(txCtx, tx, id)
		if err != nil {
			return err
		}
		auditLogEntry, err = e.ToDomain()
		return err
	})
	if err != nil {
		return nil, err
	}
	return auditLogEntry, nil
}
