package main

import (
	"fmt"

	"github.com/CalvoM/websockets"
)

func main() {
	fmt.Println("Server loading...")
	websockets.RunServer()
}
