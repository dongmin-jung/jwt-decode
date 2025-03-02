package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	prom "github.com/prometheus/client_golang/prometheus"

	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog/hlog"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog"
	"github.com/tmax-cloud/jwt-decode/decoder"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Env variable constants
const (
	JwksURLEnv                  = "JWKS_URL"
	ForceJwksOnStart            = "FORCE_JWKS_ON_START"
	ForceJwksOnStartDefault     = "true"
	ClaimMappingFileEnv         = "CLAIM_MAPPING_FILE_PATH"
	ClaimMappingFileDefault     = "config.json"
	AuthHeaderEnv               = "AUTH_HEADER_KEY"
	AuthHeaderDefault           = "Authorization"
	TokenValidatedHeaderEnv     = "TOKEN_VALIDATED_HEADER_KEY"
	TokenValidatedHeaderDefault = "jwt-token-validated"
	MultiClusterPrefixEnv       = "MULTI_CLUSTER_PREFIX"
	MultiClusterPrefixDefault   = "multicluster"
	SecretCacheTTLEnv           = "SECRET_CACHE_TTL"
	SecretCacheTTLDefault       = "300"
	PortEnv                     = "PORT"
	PortDefault                 = "8080"
	LogLevelEnv                 = "LOG_LEVEL"
	LogLevelDefault             = "info"
	LogTypeEnv                  = "LOG_TYPE"
	LogTypeDefault              = "json"
	MaxCacheKeysEnv             = "MAX_CACHE_KEYS"
	MaxCacheKeysDefault         = "10000"
	CacheEnabledEnv             = "CACHE_ENABLED"
	CacheEnabledDefault         = "true"
	ClaimMappingsEnv            = "CLAIM_MAPPINGS"
	UsernameClaimEnv            = "OIDC_USERNAME_CLAIM"
	UsernameClaimDefault        = "preferred_username"
	ValidateAPIPathsEnv         = "VALIDATE_API_PATHS"
	ValidateAPIPathsDefault     = "/api/prometheus/,/api/prometheus-tenancy/,/api/alertmanager/,/api/hypercloud/,/api/multi-hypercloud/"
)

// NewConfig creates a new Config from the current env
func NewConfig() *Config {
	var c Config
	c.jwksURL = required(JwksURLEnv)
	c.forceJwksOnStart = withDefault(ForceJwksOnStart, ForceJwksOnStartDefault)
	c.claimMappingFilePath = withDefault(ClaimMappingFileEnv, ClaimMappingFileDefault)
	c.authHeader = withDefault(AuthHeaderEnv, AuthHeaderDefault)
	c.tokenValidatedHeader = withDefault(TokenValidatedHeaderEnv, TokenValidatedHeaderDefault)
	c.multiClusterPrefix = withDefault(MultiClusterPrefixEnv, MultiClusterPrefixDefault)
	c.secretCacheTTL = withDefault(SecretCacheTTLEnv, SecretCacheTTLDefault)
	c.port = withDefault(PortEnv, PortDefault)
	c.logLevel = withDefault(LogLevelEnv, LogLevelDefault)
	c.logType = withDefault(LogTypeEnv, LogTypeDefault)
	c.maxCacheKeys = withDefault(MaxCacheKeysEnv, MaxCacheKeysDefault)
	c.cacheEnabled = withDefault(CacheEnabledEnv, CacheEnabledDefault)
	c.usernameClaim = withDefault(UsernameClaimEnv, UsernameClaimDefault)
	c.validateAPIPaths = withDefault(ValidateAPIPathsEnv, ValidateAPIPathsDefault)
	c.claimMappings = optional(ClaimMappingsEnv)
	c.keyCost = 100
	return &c
}

// Config to bootstrap decoder server
type Config struct {
	jwksURL              envVar
	forceJwksOnStart     envVar
	claimMappingFilePath envVar
	authHeader           envVar
	tokenValidatedHeader envVar
	multiClusterPrefix   envVar
	secretCacheTTL       envVar
	port                 envVar
	logLevel             envVar
	logType              envVar
	maxCacheKeys         envVar
	cacheEnabled         envVar
	claimMappings        envVar
	usernameClaim        envVar
	validateAPIPaths     envVar
	keyCost              int64
}

// RunServer starts a server from the config
func (c *Config) RunServer() (chan error, net.Listener) {
	logger := c.getLogger()
	log.Logger = logger
	registry := prom.NewRegistry()
	server := c.getServer(registry)
	var handler http.HandlerFunc = server.DecodeToken
	histogramMw := histogramMiddleware(registry)
	loggingMiddleWare := hlog.NewHandler(logger)
	serve := fmt.Sprintf(":%s", c.port.get())
	done := make(chan error)
	listener, err := net.Listen("tcp", serve)
	if err != nil {
		panic(err)
	}
	go func() {
		srv := &http.Server{}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		mux.Handle("/", histogramMw(loggingMiddleWare(handler)))
		mux.Handle("/ping", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}))
		srv.Handler = mux
		done <- srv.Serve(listener)
		close(done)
	}()
	log.Info().Msgf("server running on %s", serve)
	return done, listener
}

func (c *Config) getServer(r *prom.Registry) *decoder.Server {
	jwksURL := c.jwksURL.get()
	claimMappings := c.getClaimMappings()
	jwsDec, err := decoder.NewJwsDecoder(jwksURL, claimMappings)
	if err != nil {
		if c.forceJwksOnStart.getBool() {
			log.Warn().Err(err).Msg("Auth server has a problem")
			// panic(err)
		} else {
			log.Warn().Err(err).Msg("will try again")
		}
	}
	claimMsg := zerolog.Dict()
	for k, v := range claimMappings {
		claimMsg.Str(k, v)
	}
	log.Info().Dict("mappings", claimMsg).Msg("mappings from claim keys to header")
	var dec decoder.TokenDecoder
	if c.cacheEnabled.getBool() {
		dec = decoder.NewCachedJwtDecoder(c.getCache(r), jwsDec)
	} else {
		dec = jwsDec
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Warn().Err(err).Msg("unable to generate in-cluster config.")
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Warn().Err(err).Msg("unable to generate kubernetes clientset.")
	}
	secretCacheTTL, err := strconv.ParseInt(c.secretCacheTTL.get(), 10, 64)
	log.Warn().Err(err).Msg("unable to convert string to int64.")
	if err != nil {
		log.Warn().Err(err).Msg("unable to convert string to int64.")
	}
	return decoder.NewServer(dec, c.authHeader.get(), c.tokenValidatedHeader.get(), c.multiClusterPrefix.get(), c.jwksURL.get(), clientset, secretCacheTTL, c.validateAPIPaths.get(), c.usernameClaim.get())
}

func (c *Config) getLogger() (logger zerolog.Logger) {
	switch c.logType.get() {
	case "json":
		logger = zerolog.New(os.Stdout)
	case "pretty":
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout})
	default:
		panic(fmt.Errorf("unknown logger type %s", c.logType.get()))
	}
	logger = logger.With().Timestamp().Caller().Logger()
	level, err := zerolog.ParseLevel(c.logLevel.get())
	if err != nil {
		panic(err)
	}
	return logger.Level(level)
}

func (c *Config) getCache(r *prom.Registry) *ristretto.Cache {
	keys := c.maxCacheKeys.getInt64()
	if keys < 1 {
		panic(fmt.Errorf("Max keys need to be a positive number, was %d", keys))
	}
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,              // number of keys to track frequency of (10M).
		MaxCost:     keys * c.keyCost, // maximum cost of cache (1GB).
		BufferItems: 64,               // number of keys per Get buffer.
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	c.registerCacheMetrics(r, cache)
	return cache
}

func (c *Config) getClaimMappings() map[string]string {
	var claimMappings claimMappingsT = make(map[string]string)
	path := c.claimMappingFilePath.get()
	errFile := claimMappings.fromFile(path)
	if errFile != nil {
		log.Warn().Err(errFile).Msgf("unable to load file resolving from env only")
	}
	errString := claimMappings.fromString(c.claimMappings.get())
	if errString != nil {
		log.Warn().Err(errString).Msgf("unable to parse claimMappingsEnv from env")
		if errFile != nil {
			panic(fmt.Errorf("either file or env needs to be valid"))
		}
	}
	return claimMappings
}

type claimMappingsT map[string]string

func (c claimMappingsT) fromFile(path string) error {
	claimMappingFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer claimMappingFile.Close()
	return json.NewDecoder(claimMappingFile).Decode(&c)
}

func (c claimMappingsT) fromString(val string) error {
	mappings := strings.Split(val, ",")
	for _, mapping := range mappings {
		if len(mapping) == 0 {
			continue
		}
		lastInd := strings.LastIndex(mapping, ":")
		if lastInd == -1 {
			return fmt.Errorf("unexpected number of ':' in claim mapping '%s'", mapping)
		}
		key := mapping[:lastInd]
		value := mapping[lastInd+1:]
		c[key] = value
	}
	return nil
}

func histogramMiddleware(r *prom.Registry) func(handler http.Handler) http.Handler {
	hist := prom.NewHistogramVec(histOpts("requests"), []string{})
	r.MustRegister(hist)
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerDuration(hist, next)
	}
}

func (c *Config) registerCacheMetrics(r *prom.Registry, cache *ristretto.Cache) {
	m := cache.Metrics
	hr := prom.NewGaugeFunc(cacheOpts("hit_ratio"), m.Ratio)
	r.MustRegister(hr)
	hit := prom.NewGaugeFunc(cacheOpts("requests", "outcome", "hit"), func() float64 {
		return float64(m.Hits())
	})
	r.MustRegister(hit)
	miss := prom.NewGaugeFunc(cacheOpts("requests", "outcome", "miss"), func() float64 {
		return float64(m.Misses())
	})
	r.MustRegister(miss)
}

func cacheOpts(name string, labels ...string) prom.GaugeOpts {
	return prom.GaugeOpts{Namespace: "traefik_jwt_decode", Subsystem: "cache", Name: name,
		ConstLabels: promLabels(labels)}
}

func histOpts(name string, labels ...string) prom.HistogramOpts {
	return prom.HistogramOpts{Namespace: "traefik_jwt_decode", Subsystem: "http_server", Name: name,
		ConstLabels: promLabels(labels), Buckets: []float64{0.001, 0.005, 0.01, 0.02, 0.05, 0.1}}
}

func promLabels(labels []string) prom.Labels {
	labelMap := make(map[string]string)
	if len(labels)%2 != 0 {
		panic("labels need to be defined in pairs")
	}
	for i := 0; i < len(labels); i += 2 {
		labelMap[labels[i]] = labels[i+1]
	}
	return labelMap
}

type envVar struct {
	name, defaultValue string
	required           bool
}

func withDefault(name, defaultValue string) envVar {
	return envVar{name: name, defaultValue: defaultValue, required: true}
}

func required(name string) envVar {
	return envVar{name: name, defaultValue: "", required: true}
}

func optional(name string) envVar {
	return envVar{name: name, defaultValue: "", required: false}
}

func (e envVar) get() string {
	if val := os.Getenv(e.name); val != "" {
		return val
	}
	if e.defaultValue == "" && e.required {
		panic(fmt.Errorf("required key %s not found in env", e.name))
	}
	return e.defaultValue
}

func (e envVar) getInt64() (val int64) {
	str := e.get()
	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		panic(fmt.Errorf("has to be an integer: %w", err))
	}
	return
}

func (e envVar) getBool() (val bool) {
	str := e.get()
	switch str {
	case "true":
		return true
	case "false":
		return false
	default:
		panic(fmt.Errorf("unknown bool value %s", str))
	}
}
