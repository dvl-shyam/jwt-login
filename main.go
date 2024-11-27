package main

import (
	"fmt"
	"log"
	"net/http"
)

func main(){
	http.HandleFunc("POST /login", Login)
	http.HandleFunc("GET /home", Home)
	http.HandleFunc("GET /refresh", Refresh)
	fmt.Println("Server is running on port 8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}