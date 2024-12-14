package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/sqkam/hysteriaclient/extras/transport/udphop"
	"github.com/sqkam/hysteriaclient/internal/http"
	"github.com/sqkam/hysteriaclient/internal/proxymux"
	"github.com/sqkam/hysteriaclient/internal/sockopts"
	"github.com/sqkam/hysteriaclient/internal/socks5"
	"github.com/sqkam/hysteriaclient/internal/utils"
	"go.uber.org/zap/zapcore"

	"github.com/spf13/viper"

	"go.uber.org/zap"
)

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

var (
	cfgFile            string
	logLevel           string = "info"
	logFormat          string = "console"
	disableUpdateCheck bool
)

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	logger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

var logger *zap.Logger

type clientConfig struct {
	Server        string                `mapstructure:"server"`
	Servers       []string              `mapstructure:"servers"`
	Auth          string                `mapstructure:"auth"`
	Transport     clientConfigTransport `mapstructure:"transport"`
	Obfs          clientConfigObfs      `mapstructure:"obfs"`
	TLS           clientConfigTLS       `mapstructure:"tls"`
	QUIC          clientConfigQUIC      `mapstructure:"quic"`
	Bandwidth     clientConfigBandwidth `mapstructure:"bandwidth"`
	FastOpen      bool                  `mapstructure:"fastOpen"`
	Lazy          bool                  `mapstructure:"lazy"`
	SOCKS5        *socks5Config         `mapstructure:"socks5"`
	HTTP          *httpConfig           `mapstructure:"http"`
	TCPForwarding []tcpForwardingEntry  `mapstructure:"tcpForwarding"`
	UDPForwarding []udpForwardingEntry  `mapstructure:"udpForwarding"`
	TCPTProxy     *tcpTProxyConfig      `mapstructure:"tcpTProxy"`
	UDPTProxy     *udpTProxyConfig      `mapstructure:"udpTProxy"`
	TCPRedirect   *tcpRedirectConfig    `mapstructure:"tcpRedirect"`
	TUN           *tunConfig            `mapstructure:"tun"`
}

type clientConfigTransportUDP struct {
	HopInterval time.Duration `mapstructure:"hopInterval"`
}

type clientConfigTransport struct {
	Type string                   `mapstructure:"type"`
	UDP  clientConfigTransportUDP `mapstructure:"udp"`
}

type clientConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type clientConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander clientConfigObfsSalamander `mapstructure:"salamander"`
}

type clientConfigTLS struct {
	SNI       string `mapstructure:"sni"`
	Insecure  bool   `mapstructure:"insecure"`
	PinSHA256 string `mapstructure:"pinSHA256"`
	CA        string `mapstructure:"ca"`
}

type clientConfigQUIC struct {
	InitStreamReceiveWindow     uint64                   `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64                   `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64                   `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64                   `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration            `mapstructure:"maxIdleTimeout"`
	KeepAlivePeriod             time.Duration            `mapstructure:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool                     `mapstructure:"disablePathMTUDiscovery"`
	Sockopts                    clientConfigQUICSockopts `mapstructure:"sockopts"`
}

type clientConfigQUICSockopts struct {
	BindInterface       *string `mapstructure:"bindInterface"`
	FirewallMark        *uint32 `mapstructure:"fwmark"`
	FdControlUnixSocket *string `mapstructure:"fdControlUnixSocket"`
}

type clientConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
}

type socks5Config struct {
	Listen     string `mapstructure:"listen"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	DisableUDP bool   `mapstructure:"disableUDP"`
}

type httpConfig struct {
	Listen   string `mapstructure:"listen"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Realm    string `mapstructure:"realm"`
}

type tcpForwardingEntry struct {
	Listen string `mapstructure:"listen"`
	Remote string `mapstructure:"remote"`
}

type udpForwardingEntry struct {
	Listen  string        `mapstructure:"listen"`
	Remote  string        `mapstructure:"remote"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpTProxyConfig struct {
	Listen string `mapstructure:"listen"`
}

type udpTProxyConfig struct {
	Listen  string        `mapstructure:"listen"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpRedirectConfig struct {
	Listen string `mapstructure:"listen"`
}

type tunConfig struct {
	Name    string        `mapstructure:"name"`
	MTU     uint32        `mapstructure:"mtu"`
	Timeout time.Duration `mapstructure:"timeout"`
	Address struct {
		IPv4 string `mapstructure:"ipv4"`
		IPv6 string `mapstructure:"ipv6"`
	} `mapstructure:"address"`
	Route *struct {
		Strict      bool     `mapstructure:"strict"`
		IPv4        []string `mapstructure:"ipv4"`
		IPv6        []string `mapstructure:"ipv6"`
		IPv4Exclude []string `mapstructure:"ipv4Exclude"`
		IPv6Exclude []string `mapstructure:"ipv6Exclude"`
	} `mapstructure:"route"`
}

func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	if c.Server == "" {
		return configError{Field: "server", Err: errors.New("server address is empty")}
	}
	var addr net.Addr
	var err error
	host, port, hostPort := parseServerAddrString(c.Server)
	if len(c.Servers) > 0 {
		addr, err = udphop.ResolveUDPHopAddrs(host, port, append(c.Servers, host))
	} else if !isPortHoppingPort(port) {
		addr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		addr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = addr
	// Special handling for SNI
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	}
	return nil
}

// fillConnFactory must be called after fillServerAddr, as we have different logic
// for ConnFactory depending on whether we have a port hopping address.
func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	so := &sockopts.SocketOptions{
		BindInterface:       c.QUIC.Sockopts.BindInterface,
		FirewallMark:        c.QUIC.Sockopts.FirewallMark,
		FdControlUnixSocket: c.QUIC.Sockopts.FdControlUnixSocket,
	}
	if err := so.CheckSupported(); err != nil {
		var unsupportedErr *sockopts.UnsupportedError
		if errors.As(err, &unsupportedErr) {
			return configError{
				Field: "quic.sockopts." + unsupportedErr.Field,
				Err:   errors.New("unsupported on this platform"),
			}
		}
		return configError{Field: "quic.sockopts", Err: err}
	}
	// Inner PacketConn
	var newFunc func(addr net.Addr) (net.PacketConn, error)

	switch strings.ToLower(c.Transport.Type) {
	case "", "udp":
		switch hyConfig.ServerAddr.Network() {
		case "udphop", "udphopx":
			hopAddr := hyConfig.ServerAddr.(udphop.Addrs)
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return udphop.NewUDPHopPacketConn(hopAddr, c.Transport.UDP.HopInterval, so.ListenUDP)
			}
		default:
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return so.ListenUDP()
			}
		}

	default:
		return configError{Field: "transport.type", Err: errors.New("unsupported transport type")}
	}
	// Obfuscation
	var ob obfs.Obfuscator
	var err error
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		// Keep it nil
	case "salamander":
		ob, err = obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return configError{Field: "obfs.salamander.password", Err: err}
		}
	default:
		return configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
	hyConfig.ConnFactory = &adaptiveConnFactory{
		NewFunc:    newFunc,
		Obfuscator: ob,
	}
	return nil
}

type adaptiveConnFactory struct {
	NewFunc    func(addr net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator // nil if no obfuscation
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	if f.Obfuscator == nil {
		return f.NewFunc(addr)
	} else {
		conn, err := f.NewFunc(addr)
		if err != nil {
			return nil, err
		}
		return obfs.WrapPacketConn(conn, f.Obfuscator), nil
	}
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	hyConfig.Auth = c.Auth
	return nil
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if c.TLS.SNI != "" {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		hyConfig.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return configError{Field: "tls.ca", Err: err}
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	// New core now allows users to omit bandwidth values and use built-in congestion control
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = utils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = utils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

// URI generates a URI for sharing the config with others.
// Note that only the bare minimum of information required to
// connect to the server is included in the URI, specifically:
// - server address
// - authenticationf
// - obfuscation type
// - obfuscation password
// - TLS SNI
// - TLS insecure
// - TLS pinned SHA256 hash (normalized)
func (c *clientConfig) URI() string {
	q := url.Values{}
	switch strings.ToLower(c.Obfs.Type) {
	case "salamander":
		q.Set("obfs", "salamander")
		q.Set("obfs-password", c.Obfs.Salamander.Password)
	}
	if c.TLS.SNI != "" {
		q.Set("sni", c.TLS.SNI)
	}
	if c.TLS.Insecure {
		q.Set("insecure", "1")
	}
	if c.TLS.PinSHA256 != "" {
		q.Set("pinSHA256", normalizeCertHash(c.TLS.PinSHA256))
	}
	var user *url.Userinfo
	if c.Auth != "" {
		// We need to handle the special case of user:pass pairs
		rs := strings.SplitN(c.Auth, ":", 2)
		if len(rs) == 2 {
			user = url.UserPassword(rs[0], rs[1])
		} else {
			user = url.User(c.Auth)
		}
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     user,
		Host:     c.Server,
		Path:     "/",
		RawQuery: q.Encode(),
	}
	return u.String()
}

// parseURI tries to parse the server address field as a URI,
// and fills the config with the information contained in the URI.
// Returns whether the server address field is a valid URI.
// This allows a user to use put a URI as the server address and
// omit the fields that are already contained in the URI.
func (c *clientConfig) parseURI() bool {
	u, err := url.Parse(c.Server)
	if err != nil {
		return false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return false
	}
	if u.User != nil {
		auth, err := url.QueryUnescape(u.User.String())
		if err != nil {
			return false
		}
		c.Auth = auth
	}
	c.Server = u.Host
	q := u.Query()
	if obfsType := q.Get("obfs"); obfsType != "" {
		c.Obfs.Type = obfsType
		switch strings.ToLower(obfsType) {
		case "salamander":
			c.Obfs.Salamander.Password = q.Get("obfs-password")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		c.TLS.SNI = sni
	}
	if insecure, err := strconv.ParseBool(q.Get("insecure")); err == nil {
		c.TLS.Insecure = insecure
	}
	if pinSHA256 := q.Get("pinSHA256"); pinSHA256 != "" {
		c.TLS.PinSHA256 = pinSHA256
	}
	return true
}

func (c *clientConfig) Config() (*client.Config, error) {
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	return hyConfig, nil
}

type clientModeRunner struct {
	ModeMap map[string]func() error
}

type clientModeRunnerResult struct {
	OK  bool
	Msg string
	Err error
}

func (r *clientModeRunner) Add(name string, f func() error) {
	if r.ModeMap == nil {
		r.ModeMap = make(map[string]func() error)
	}
	r.ModeMap[name] = f
}

func (r *clientModeRunner) Run() clientModeRunnerResult {
	if len(r.ModeMap) == 0 {
		return clientModeRunnerResult{OK: false, Msg: "no mode specified"}
	}

	type modeError struct {
		Name string
		Err  error
	}
	errChan := make(chan modeError, len(r.ModeMap))
	for name, f := range r.ModeMap {
		go func(name string, f func() error) {
			err := f()
			errChan <- modeError{name, err}
		}(name, f)
	}
	// Fatal if any one of the modes fails
	for i := 0; i < len(r.ModeMap); i++ {
		e := <-errChan
		if e.Err != nil {
			return clientModeRunnerResult{OK: false, Msg: "failed to run " + e.Name, Err: e.Err}
		}
	}

	// We don't really have any such cases, as currently none of our modes would stop on themselves without error.
	// But we leave the possibility here for future expansion.
	return clientModeRunnerResult{OK: true, Msg: "finished without error"}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.SupportedExts = append([]string{"yaml", "yml"}, viper.SupportedExts...)
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.hysteria")
		viper.AddConfigPath("/etc/hysteria/")
	}
}

func run(config clientConfig, runnerChan chan clientModeRunnerResult) {
	c, err := client.NewReconnectableClient(
		config.Config,
		func(c client.Client, info *client.HandshakeInfo, count int) {
			connectLog(info, count)
			// On the client side, we start checking for updates after we successfully connect
			// to the server, which, depending on whether lazy mode is enabled, may or may not
			// be immediately after the client starts. We don't want the update check request
			// to interfere with the lazy mode option.
		}, config.Lazy)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()

	uri := config.URI()
	logger.Info("use this URI to share your server", zap.String("uri", uri))

	var runner clientModeRunner
	if config.SOCKS5 != nil {
		runner.Add("SOCKS5 server", func() error {
			return clientSOCKS5(*config.SOCKS5, c)
		})
	}

	if config.HTTP != nil {
		runner.Add("HTTP proxy server", func() error {
			return clientHTTP(*config.HTTP, c)
		})
	}
	r := runner.Run()
	runnerChan <- r
	c.Close()

	if r.Err != nil {
		logger.Fatal(r.Msg, zap.Error(r.Err))
	} else {
		logger.Fatal(r.Msg)
	}
}

func main() {
	Run()
}

func Run() {
	initLogger()
	initConfig()
	logger.Info("client mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var hyConfig struct {
		Hys []clientConfig `mapstructure:"hys"`
	}

	if err := viper.Unmarshal(&hyConfig); err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runnerChan := make(chan clientModeRunnerResult, len(hyConfig.Hys))

	for _, v := range hyConfig.Hys {
		go run(v, runnerChan)
	}

	select {
	case <-signalChan:
		logger.Info("received signal, shutting down gracefully")
	case r := <-runnerChan:
		if r.OK {
			logger.Info(r.Msg)
		} else {
			// Close the client here as Fatal will exit the program without running defer
			if r.Err != nil {
				logger.Fatal(r.Msg, zap.Error(r.Err))
			} else {
				logger.Fatal(r.Msg)
			}
		}
	}
}

func clientSOCKS5(config socks5Config, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := proxymux.ListenSOCKS(config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	s := socks5.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		DisableUDP:  config.DisableUDP,
		EventLogger: &socks5Logger{},
	}
	logger.Info("SOCKS5 server listening", zap.String("addr", config.Listen))
	return s.Serve(l)
}

func connectLog(info *client.HandshakeInfo, count int) {
	logger.Info("connected to server",
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx),
		zap.Int("count", count))
}

type socks5Logger struct{}

func (l *socks5Logger) TCPRequest(addr net.Addr, reqAddr string) {
	logger.Debug("SOCKS5 TCP request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *socks5Logger) TCPError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("SOCKS5 TCP closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("SOCKS5 TCP error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *socks5Logger) UDPRequest(addr net.Addr) {
	logger.Debug("SOCKS5 UDP request", zap.String("addr", addr.String()))
}

func (l *socks5Logger) UDPError(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("SOCKS5 UDP closed", zap.String("addr", addr.String()))
	} else {
		logger.Warn("SOCKS5 UDP error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

func clientHTTP(config httpConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := proxymux.ListenHTTP(config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	if config.Realm == "" {
		config.Realm = "Hysteria"
	}
	h := http.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		AuthRealm:   config.Realm,
		EventLogger: &httpLogger{},
	}
	logger.Info("HTTP proxy server listening", zap.String("addr", config.Listen))
	return h.Serve(l)
}

type httpLogger struct{}

func (l *httpLogger) ConnectRequest(addr net.Addr, reqAddr string) {
	logger.Debug("HTTP CONNECT request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *httpLogger) ConnectError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("HTTP CONNECT closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("HTTP CONNECT error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *httpLogger) HTTPRequest(addr net.Addr, reqURL string) {
	logger.Debug("HTTP request", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
}

func (l *httpLogger) HTTPError(addr net.Addr, reqURL string, err error) {
	if err == nil {
		logger.Debug("HTTP closed", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
	} else {
		logger.Warn("HTTP error", zap.String("addr", addr.String()), zap.String("reqURL", reqURL), zap.Error(err))
	}
}
