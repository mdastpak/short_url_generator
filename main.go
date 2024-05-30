package main

import (
	"fmt"
	"log"
	"net/http"

	"short-url-generator/config"
	"short-url-generator/handler"

	"github.com/gorilla/mux"
)

func main() {
	cfg := config.MustLoadConfig()

	handler.InitHandlers(cfg.Redis)

	r := mux.NewRouter()
	r.HandleFunc("/shorten", handler.CreateShortURL).Methods("POST")
	r.HandleFunc("/{shortURL}", handler.RedirectURL).Methods("GET")

	serverAddress := fmt.Sprintf("%s:%s", cfg.WebServer.IP, cfg.WebServer.Port)
	log.Printf("Starting server at %s...", serverAddress)
	if err := http.ListenAndServe(serverAddress, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
