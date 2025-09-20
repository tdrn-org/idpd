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

package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

const undefined = "<dev build>"

var cmd = undefined
var version = undefined
var timestamp = undefined

func Cmd() string {
	return cmd
}

func Version() string {
	return version
}

func Timestamp() string {
	return timestamp
}

func FullVersion() string {
	return fmt.Sprintf("idpd version %s (%s) %s/%s", Version(), Timestamp(), runtime.GOOS, runtime.GOARCH)
}

func Extended() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "<no build info>"
	}
	buffer := &strings.Builder{}
	fmt.Fprint(buffer, "Build toolchain ", buildInfo.GoVersion)
	for _, setting := range buildInfo.Settings {
		fmt.Fprintln(buffer)
		fmt.Fprint(buffer, "  ", setting.Key, "=", strconv.Quote(setting.Value))
	}
	return buffer.String()
}
