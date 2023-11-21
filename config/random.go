package config

import (
	"fmt"
	"math/rand"
	"time"
)

func initRandom() {
	fmt.Print("random init... ")
	rand.Seed(time.Now().UnixNano())
	fmt.Println("OK")
}
