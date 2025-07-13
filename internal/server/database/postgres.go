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

import (
	_ "embed"
	"log/slog"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed postgres_schema1.sql
var postgresSchema1Script []byte

func OpenPostgresDB(url string, logger *slog.Logger) (Driver, error) {
	return openDatabase("PostgreSQL", "pgx", url, logger, postgresSchema1Script)
}
