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

package idpd

import (
	"context"
	"log/slog"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-conf/service/loglevel"
)

var cmdLineVars = kong.Vars{
	"config_default": DefaultConfig,
}

type cmdLine struct {
	Silent  bool   `short:"s" help:"Enable silent mode (log level error)"`
	Quiet   bool   `short:"q" help:"Enable quiet mode (log level warn)"`
	Verbose bool   `short:"v" help:"Enable verbose output (log level info)"`
	Debug   bool   `short:"d" help:"Enable debug output (log level debug)"`
	RunCmd  runCmd `cmd:"" name:"run" default:"withargs" help:"run server"`
	ctx     context.Context
}

type runCmd struct {
	Config string `short:"c" help:"The configuration file to use" default:"${config_default}"`
}

func (cmd *runCmd) Run(args *cmdLine) error {
	config, err := cmd.loadConfig()
	if err != nil {
		return err
	}
	cmd.applyGlobalArgs(config, args)
	cmd.initLogging(config)
	s, err := startConfig(args.ctx, config)
	if err != nil {
		return err
	}
	s.WaitStopped()
	return nil
}

func (cmd *runCmd) loadConfig() (*Config, error) {
	path := strings.TrimSpace(cmd.Config)
	if path == "" {
		path = DefaultConfig
	}
	return LoadConfig(path, false)
}

func (cmd *runCmd) applyGlobalArgs(config *Config, args *cmdLine) {
	if args.Debug {
		config.Logging.Level = slog.LevelDebug.String()
	} else if args.Verbose {
		config.Logging.Level = slog.LevelInfo.String()
	} else if args.Quiet {
		config.Logging.Level = slog.LevelWarn.String()
	} else if args.Silent {
		config.Logging.Level = slog.LevelError.String()
	}
}

func (cmd *runCmd) initLogging(config *Config) {
	logLevel, _ := conf.LookupService[loglevel.LogLevelService]()
	logger, _ := config.toLogConfig().GetLogger(logLevel.LevelVar())
	slog.SetDefault(logger)
}
