package main

import (
	"fmt"
	"net/http"
	"work/config"
	"work/result"
	"work/routes"

	"github.com/gorilla/mux"
)

func main() {
	config.InitConfig()
	routeAll := mux.NewRouter()
	routes.GetAllHandlers(routeAll)
	routeAll.Use(mw)
	routeAll.Methods("OPTIONS").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			res := result.SetErrorResult(`опять балуется CORS :(`)
			result.ReturnJSON(w, &res)
		})
	http.Handle("/", routeAll)
	fmt.Println("[SERVER] Server address is 127.0.0.1:8080")
	//	go http.ListenAndServeTLS(APP_IP+":"+APP_PORT, "cert.crt", "key.key", nil)
	fmt.Println("[SERVER] Server is started")
	http.ListenAndServe("127.0.0.1:8080", nil)
	fmt.Println("[SERVER] Server is started")
}

func mw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
