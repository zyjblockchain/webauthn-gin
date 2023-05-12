package main

import (
	webauthn_gin "github.com/zyjblockchain/webauthn-gin"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	dsn := "root@tcp(127.0.0.1:3306)/webauthn?charset=utf8mb4&parseTime=True&loc=Local"
	s := webauthn_gin.NewServer(dsn)
	s.Run()

	<-signals
}
