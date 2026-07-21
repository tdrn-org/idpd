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

package config

import (
	"fmt"
	"log/slog"

	"github.com/tdrn-org/go-log"
)

type LoggingConfig struct {
	Level          LogLevel  `toml:"level"`
	Target         LogTarget `toml:"target"`
	Color          LogColor  `toml:"color"`
	FileName       string    `toml:"file_name"`
	FileSizeLimit  int64     `toml:"file_size_limit"`
	SyslogNetwork  string    `toml:"syslog_network"`
	SyslogAddress  string    `toml:"syslog_address"`
	SyslogEncoding string    `toml:"syslog_encoding"`
	SyslogFacility int       `toml:"syslog_facility"`
}

type LogLevel slog.Level

var knownLogLevels map[string]LogLevel = map[string]LogLevel{
	"debug": LogLevel(slog.LevelDebug),
	"info":  LogLevel(slog.LevelInfo),
	"warn":  LogLevel(slog.LevelWarn),
	"error": LogLevel(slog.LevelError),
}

func (l *LogLevel) Value() string {
	for value, level := range knownLogLevels {
		if *l == level {
			return value
		}
	}
	slog.Warn("unexpected log level", slog.Any("l", *l))
	return ""
}

func (l *LogLevel) MarshalTOML() ([]byte, error) {
	return []byte(`"` + l.Value() + `"`), nil
}

func (l *LogLevel) UnmarshalTOML(value any) error {
	levelString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected log level type %v", value)
	}
	level, ok := knownLogLevels[levelString]
	if !ok {
		return fmt.Errorf("unknown log level: '%s'", levelString)
	}
	*l = level
	return nil
}

type LogTarget log.Target

var knownLogTargets map[string]LogTarget = map[string]LogTarget{
	string(log.TargetStdout):     LogTarget(log.TargetStdout),
	string(log.TargetStdoutText): LogTarget(log.TargetStdoutText),
	string(log.TargetStdoutJSON): LogTarget(log.TargetStdoutJSON),
	string(log.TargetStderr):     LogTarget(log.TargetStderr),
	string(log.TargetStderrText): LogTarget(log.TargetStderrText),
	string(log.TargetStderrJSON): LogTarget(log.TargetStderrJSON),
	string(log.TargetFileText):   LogTarget(log.TargetFileText),
	string(log.TargetFileJSON):   LogTarget(log.TargetFileJSON),
	string(log.TargetSyslog):     LogTarget(log.TargetSyslog),
}

func (t *LogTarget) Value() string {
	for value, target := range knownLogTargets {
		if *t == target {
			return value
		}
	}
	slog.Warn("unexpected log target", slog.Any("t", *t))
	return ""
}

func (t *LogTarget) MarshalTOML() ([]byte, error) {
	return []byte(`"` + t.Value() + `"`), nil
}

func (t *LogTarget) UnmarshalTOML(value any) error {
	targetString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected log target type %v", value)
	}
	target, ok := knownLogTargets[targetString]
	if !ok {
		return fmt.Errorf("unknown log target: '%s'", targetString)
	}
	*t = target
	return nil
}

type LogColor log.Color

var knownLogColors map[string]LogColor = map[string]LogColor{
	"auto": LogColor(log.ColorAuto),
	"off":  LogColor(log.ColorOff),
	"on":   LogColor(log.ColorOn),
}

func (c *LogColor) Value() string {
	for value, color := range knownLogColors {
		if *c == color {
			return value
		}
	}
	slog.Warn("unexpected log color", slog.Any("c", *c))
	return ""
}

func (c *LogColor) MarshalTOML() ([]byte, error) {
	return []byte(`"` + c.Value() + `"`), nil
}

func (c *LogColor) UnmarshalTOML(value any) error {
	colorString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected log color type %v", value)
	}
	color, ok := knownLogColors[colorString]
	if !ok {
		return fmt.Errorf("unknown log color: '%s'", colorString)
	}
	*c = color
	return nil
}
