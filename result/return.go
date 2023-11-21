package result

import (
	"encoding/json"
	"net/http"
)

type Returning interface{}

type ResultInfo struct {
	Done      bool        `json:"done"`
	Message   *string     `json:"message,omitempty"`
	Items     interface{} `json:"data,omitempty"`
	Paginator *Paginator  `json:"paginator,omitempty"`
}

type Paginator struct {
	Total     int `json:"total"`
	CountPage int `json:"count_page"`
	Page      int `json:"page"`
	Offset    int `json:"offset"`
	Limit     int `json:"limit"`
}

func SetErrorResult(m string) (result ResultInfo) {
	result.Done = false
	result.Message = &m
	result.Items = nil
	return result
}

func ReturnJSON(w http.ResponseWriter, object Returning) {
	ansB, err := json.Marshal(object)
	if err != nil {
		ErrorServer(nil, err)
	}
	Headers(w)
	_, err = w.Write(ansB)
	if err != nil {
		ErrorServer(nil, err)
	}
}

func Headers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
}
