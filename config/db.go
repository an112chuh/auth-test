package config

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

var Db *sql.DB

func initDb() {
	fmt.Print("sqlite3 init... ")
	db, err := sql.Open("sqlite3", "work.db")
	if err != nil {
		fmt.Println("ERR")
		panic(err)
	}
	Db = db
	fmt.Println("OK")
}

func GetConnection() (db *sql.DB) {
	return Db
}
