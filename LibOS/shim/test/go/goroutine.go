// From https://tour.golang.org/concurrency/1/

package main

import (
	"fmt"
	"time"
)

func say(s string) {
	for i := 0; i < 5; i++ {
		fmt.Println(s)
	}
}

func main() {
	fmt.Println("begin");
	go say("world")
	say("hello")
	time.Sleep(100 * time.Millisecond)
}
