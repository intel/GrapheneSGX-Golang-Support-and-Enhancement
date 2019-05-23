// From https://tour.golang.org/concurrency/1/

package main

import (
    "os"
    "syscall"
    "fmt"
)

func main() {
    fmt.Println("begin");

    var buf [0x1000]byte
    fmt.Println("syscall.Getcwd")
    n, err0 := syscall.Getcwd(buf[0:])
    fmt.Printf("syscall.Getcwd %s %s \"%s\"\n", n, err0, string(buf[:n]))

    fmt.Println("syscall.Getwd")
    s1, err1 := syscall.Getwd()
    fmt.Println("syscall.Getwd \"", s1, "\" \"", err1, "\"")

    fmt.Println("os.Getwd")
    s, err := os.Getwd()
    fmt.Println("os.Getwd \"", s, "\" \"", err, "\"")
}
