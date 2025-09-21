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
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-conf/service/loglevel"
	"github.com/tdrn-org/go-diff"
	"github.com/tdrn-org/idpd/internal/buildinfo"
)

var cmdLineApplication = kong.Name(buildinfo.Cmd())

var cmdLineHelpOptions = kong.ConfigureHelp(kong.HelpOptions{
	Compact: true,
})

var cmdLineVars = kong.Vars{
	"config_default": DefaultConfig,
}

type cmdLine struct {
	Silent      bool            `short:"s" help:"Enable silent mode (log level error)"`
	Quiet       bool            `short:"q" help:"Enable quiet mode (log level warn)"`
	Verbose     bool            `short:"v" help:"Enable verbose output (log level info)"`
	Debug       bool            `short:"d" help:"Enable debug output (log level debug)"`
	RunCmd      runCmd          `cmd:"" name:"run" default:"withargs" help:"run server"`
	VersionCmd  versionCmd      `cmd:"" name:"version" help:"show version info"`
	TemplateCmd templateCmd     `cmd:"" name:"template" help:"output config template"`
	ctx         context.Context `kong:"-"`
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

type versionCmd struct {
	Extended bool `short:"x" help:"Output extended version info"`
}

func (cmd *versionCmd) Run(args *cmdLine) error {
	fmt.Println(buildinfo.FullVersion())
	if args.VersionCmd.Extended {
		fmt.Println(buildinfo.Extended())
	}
	return nil
}

type templateCmd struct {
	Diff string `help:"The configuration file to compare the config template to"`
}

//go:embed config_template.toml
var template string

func (cmd *templateCmd) Run(args *cmdLine) error {
	if cmd.Diff == "" {
		fmt.Print(template)
	} else {
		diffFile, err := os.Open(cmd.Diff)
		if err != nil {
			return fmt.Errorf("unable to open file '%s' (cause: %w)", cmd.Diff, err)
		}
		defer diffFile.Close()
		diffResult, err := diff.Diff(strings.NewReader(template), diffFile)
		if err != nil {
			return fmt.Errorf("failed to compare configurations (cause: %w)", err)
		}
		diff.NewPrinter(os.Stdout).Print(diffResult)
	}
	return nil
}
