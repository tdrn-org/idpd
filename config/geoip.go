package config

import (
	"fmt"
	"log/slog"

	"github.com/tdrn-org/idpd/internal/geoip"
	"github.com/tdrn-org/idpd/internal/geoip/maxminddb"
)

type GeoIPConfig struct {
	Provider GeoIPProvider `toml:"provider"`
	Mappings []struct {
		Networks NetworkSpecs `toml:"networks"`
		Host     string       `toml:"host"`
	} `toml:"mapping"`
	None      struct{} `toml:"none"`
	MaxMindDB struct {
		File string `toml:"file"`
	} `toml:"maxminddb"`
}

type GeoIPProvider geoip.ProviderName

var knownGeoIPProviders map[string]GeoIPProvider = map[string]GeoIPProvider{
	string(geoip.NoneProviderName): GeoIPProvider(geoip.NoneProviderName),
	string(maxminddb.ProviderName): GeoIPProvider(maxminddb.ProviderName),
}

func (p *GeoIPProvider) Value() string {
	for value, geoipProvider := range knownGeoIPProviders {
		if *p == geoipProvider {
			return value
		}
	}
	slog.Warn("unexpected GeoIP provider", slog.Any("p", *p))
	return ""
}

func (p *GeoIPProvider) MarshalTOML() ([]byte, error) {
	return []byte(`"` + p.Value() + `"`), nil
}

func (p *GeoIPProvider) UnmarshalTOML(value any) error {
	geoipProviderString, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected GeoIP provider type %v", value)
	}
	geoipProvider, ok := knownGeoIPProviders[geoipProviderString]
	if !ok {
		return fmt.Errorf("unknown GeoIP provider: '%s'", geoipProviderString)
	}
	*p = geoipProvider
	return nil
}
