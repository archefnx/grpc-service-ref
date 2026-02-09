package main

import (
	"fmt"
	"grpc-service-ref/internal/config"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)
}
