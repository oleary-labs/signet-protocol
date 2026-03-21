package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	fmt.Println("Serving on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
