package main

import (
	"github.com/metacubex/mihomo/component/resolver"
	_ "github.com/metacubex/mihomo/dns"
	"github.com/spf13/viper"

	"github.com/sqkam/hysteriaclient/app"
)

var cfgFile string

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

func main() {
	initConfig()
	var hyConfig app.HyConfig
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := viper.Unmarshal(&hyConfig); err != nil {
		panic(err)
	}
	resolver.DisableIPv6 = false
	app.Run(hyConfig, nil)
}
