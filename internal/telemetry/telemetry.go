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

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

type Config struct {
	Enabled       bool
	Domain        string
	EndpointURL   *url.URL
	Protocol      string
	BatchTimeout  time.Duration
	ExportTimeout time.Duration
}

func (c *Config) Apply() (func(context.Context) error, error) {
	if !c.Enabled {
		return shutdownFuncs{}.Run, nil
	}
	var exporter *otlptrace.Exporter
	var err error
	switch c.Protocol {
	case "http":
		exporter, err = c.newHttpExporter()
	case "gRPC":
		exporter, err = c.newGRPCExporter()
	default:
		return nil, fmt.Errorf("unrecognized tracing protocol: '%s'", c.Protocol)
	}
	if err != nil {
		return nil, err
	}
	batcherOpts := []tracesdk.BatchSpanProcessorOption{
		tracesdk.WithBatchTimeout(c.BatchTimeout),
		tracesdk.WithExportTimeout(c.BatchTimeout),
	}
	provider := tracesdk.NewTracerProvider(tracesdk.WithBatcher(exporter, batcherOpts...))
	otel.SetTracerProvider(&domainTracerProvider{domain: c.Domain, provider: provider})
	shutdowns := shutdownFuncs{provider.Shutdown, exporter.Shutdown}
	return shutdowns.Run, nil
}

func (c *Config) newHttpExporter() (*otlptrace.Exporter, error) {
	opts := make([]otlptracehttp.Option, 0, 2)
	opts = append(opts, otlptracehttp.WithEndpointURL(c.EndpointURL.String()))
	if c.EndpointURL.Scheme == "http" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP/HTTP exporter (cause: %w)", err)
	}
	return exporter, nil
}

func (c *Config) newGRPCExporter() (*otlptrace.Exporter, error) {
	opts := make([]otlptracegrpc.Option, 0, 2)
	opts = append(opts, otlptracegrpc.WithEndpointURL(c.EndpointURL.String()))
	if c.EndpointURL.Scheme == "http" {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP/gRPC exporter (cause: %w)", err)
	}
	return exporter, nil
}

type domainTracerProvider struct {
	embedded.TracerProvider
	domain   string
	provider trace.TracerProvider
}

func (p *domainTracerProvider) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	return p.provider.Tracer(p.domain+"/"+name, opts...)
}

type shutdownFuncs []func(context.Context) error

func (shutdowns shutdownFuncs) Run(ctx context.Context) error {
	errs := make([]error, 0, len(shutdowns))
	for _, shutdown := range shutdowns {
		errs = append(errs, shutdown(ctx))
	}
	return errors.Join(errs...)
}
