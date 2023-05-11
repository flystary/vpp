//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	f, err := ioutil.ReadFile("./interface.log")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(f))
}
