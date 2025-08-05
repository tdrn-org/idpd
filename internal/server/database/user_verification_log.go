/*
 * Copyright 2025 Holger de Carne
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

package database

import "time"

type UserVerificationLog struct {
	Subject     string
	Method      string
	FirstUsed   int64
	LastUsed    int64
	Host        string
	Country     string
	CountryCode string
	Lat         float64
	Lon         float64
}

func NewUserVerificationLog(subject string, method string, host string) *UserVerificationLog {
	now := time.Now().UnixMicro()
	return &UserVerificationLog{
		Subject:   subject,
		Method:    method,
		FirstUsed: now,
		LastUsed:  now,
		Host:      host,
	}
}

func (l *UserVerificationLog) Update(log *UserVerificationLog) {
	l.LastUsed = log.LastUsed
	l.Host = log.Host
	l.Country = log.Country
	l.CountryCode = log.CountryCode
	l.Lat = log.Lat
	l.Lon = log.Lon
}
