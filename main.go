package main

import (
	"fmt"

	"github.com/CalvoM/websockets/wsserver"
)

func main() {
	fmt.Println("Server loading...")
	wsserver.RunServer()
}
