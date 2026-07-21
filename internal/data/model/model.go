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
	_ "embed"

	"github.com/tdrn-org/go-database/postgres"
	"github.com/tdrn-org/go-database/sqlite"
)

//go:embed schema.sqlite.1.sql
var schemaSQLite1Script []byte
var SqliteSchemaScriptOption sqlite.ConfigSetter = sqlite.WithSchemaScripts(schemaSQLite1Script)

//go:embed schema.postgres.1.sql
var schemaPostgres1Script []byte
var PostgresSchemaScriptOption postgres.ConfigSetter = postgres.WithSchemaScripts(schemaPostgres1Script)
