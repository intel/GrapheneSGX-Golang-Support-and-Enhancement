package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("hello")
	time.Sleep(100 * time.Millisecond)
	fmt.Println("world")
}
