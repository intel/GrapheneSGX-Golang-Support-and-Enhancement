// from https://groups.google.com/forum/#!topic/golang-nuts/tHhNMi2wykg
package main

import (
    "fmt"
    "net"
)

func wait() {
    a, _ := net.Pipe()
    c := make([]byte, 100)
    a.Read(c)
    fmt.Printf("ORLY?\n")
}

func main() {
    for i := 0; i < 100000; i++ {
        fmt.Printf("%d: OK\n", i)
        go wait()
    }
    fmt.Printf("All OK\n")
}
