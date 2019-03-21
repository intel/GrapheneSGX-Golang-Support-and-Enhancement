package main

import (
	"fmt"
	"os"
	"time"
	"syscall"
)

func say() {
	fmt.Fprintf(os.Stdout, "hello go tid: %d\n", syscall.Gettid())
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintf(os.Stdout, "world go tid: %d\n", syscall.Gettid())
}

func main() {
	fmt.Fprintf(os.Stdout, "GOGC=%s\n", os.Getenv("GOGC"))
	go say()
	fmt.Fprintf(os.Stdout, "hello parent tid: %d\n", syscall.Gettid())
	time.Sleep(500 * time.Millisecond)
	fmt.Fprintf(os.Stdout, "world parent tid: %d\n", syscall.Gettid())
}
