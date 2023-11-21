package routes

import (
	"work/handlers"

	"github.com/gorilla/mux"
)

func GetAllHandlers(r *mux.Router) {
	r.HandleFunc("/api/login", handlers.LoginHandler)
	r.HandleFunc("/api/refresh", handlers.RefreshHandler)
	r.HandleFunc("/api/delete", handlers.DeleteHandler)
	r.HandleFunc("/api/delete_all", handlers.DeleteAllHandler)
}
