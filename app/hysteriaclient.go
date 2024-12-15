package app

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sqkam/hysteriaclient/internal/proxymux"

	"github.com/apernet/hysteria/core/v2/client"
	L "github.com/sagernet/sing/common/logger"
	"github.com/sqkam/hysteriaclient/internal/http"
	"github.com/sqkam/hysteriaclient/internal/socks5"
	hL "github.com/sqkam/hysteriaclient/logger"
	"go.uber.org/zap"
)

var (
	cfgFile string

	disableUpdateCheck bool
)

func run(ctx context.Context, config clientConfig, runnerChan chan clientModeRunnerResult) {
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
		runner.Add("SOCKS5 server", func(ctx context.Context) error {
			return clientSOCKS5(ctx, *config.SOCKS5, c)
		})
	}

	if config.HTTP != nil {
		runner.Add("HTTP proxy server", func(ctx context.Context) error {
			return clientHTTP(ctx, *config.HTTP, c)
		})
	}
	r := runner.Run(ctx)
	runnerChan <- r

	if r.Err != nil {
		logger.Fatal(r.Msg, zap.Error(r.Err))
	} else {
		logger.Info(r.Msg)
	}
}

type HyConfig struct {
	Hys []clientConfig `mapstructure:"hys"`
}

var logger L.Logger

func Run(ctx context.Context, hyConfig HyConfig, logger2 L.Logger) {
	logger = hL.SingLogger
	if logger2 != nil {
		logger = hL.NewAppendLogger(logger2)
	}
	logger.Info("client mode")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runnerChan := make(chan clientModeRunnerResult, len(hyConfig.Hys))

	for _, v := range hyConfig.Hys {
		go run(ctx, v, runnerChan)
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

func clientSOCKS5(ctx context.Context, config socks5Config, c client.Client) error {
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
	return s.Serve(ctx, l)
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

func clientHTTP(ctx context.Context, config httpConfig, c client.Client) error {
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
	return h.Serve(ctx, l)
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
