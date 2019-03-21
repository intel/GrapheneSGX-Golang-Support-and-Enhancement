// From https://tour.golang.org/concurrency/1/

package main

import (
	"fmt"
	"time"
	"os"
)

func say(s string) {
	for i := 0; i < 5; i++ {
		//fmt.Printf("%s %d\n", s, i)
		fmt.Fprintf(os.Stdout, "%s %d\n", s, i)
		time.Sleep(100 * time.Millisecond)
		//fmt.Println(s)
	}
}

func main() {
	go say("hello")
	time.Sleep(10 * 100 * time.Millisecond)
	fmt.Println("world")
}
