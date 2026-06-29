package main

import (
	"log"
	"os"
	"sync"

	grpcapi "github.com/deepint-shield/ai-security-guard/internal/api/grpcapi"
	"github.com/deepint-shield/ai-security-guard/internal/api/httpapi"
	"github.com/deepint-shield/ai-security-guard/internal/engine"
)

func main() {
	httpAddr := os.Getenv("DEEPINTSHIELD_GUARD_ADDR")
	if httpAddr == "" {
		httpAddr = ":8091"
	}
	grpcAddr := os.Getenv("DEEPINTSHIELD_GUARD_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = ":8092"
	}
	sharedSecret := os.Getenv("DEEPINTSHIELD_GUARD_SHARED_SECRET")

	runtime := engine.New()
	httpServer := httpapi.NewServer(runtime, sharedSecret)
	grpcServer := grpcapi.NewServer(runtime, sharedSecret)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		log.Printf("deepintshield_guard HTTP listening on %s", httpAddr)
		if err := httpServer.ListenAndServe(httpAddr); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		defer wg.Done()
		log.Printf("deepintshield_guard gRPC listening on %s", grpcAddr)
		if err := grpcServer.ListenAndServe(grpcAddr); err != nil {
			log.Fatal(err)
		}
	}()
	wg.Wait()
}
