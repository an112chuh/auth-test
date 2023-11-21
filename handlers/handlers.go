package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
	"work/config"
	"work/result"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var res result.ResultInfo
	vars := r.URL.Query()
	if len(vars["guid"]) == 0 {
		res = result.SetErrorResult(`Неверный параметр GUID`)
		result.ReturnJSON(w, &res)
		return
	}
	guid := vars["guid"][0]
	res = createLogin(guid)
	result.ReturnJSON(w, &res)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var res result.ResultInfo
	if r.Header["Accesstoken"] == nil || r.Header["Refreshtoken"] == nil {
		res = result.SetErrorResult(`Отсутствуют токены в хедере`)
		result.ReturnJSON(w, &res)
		return
	}
	accessToken := r.Header["Accesstoken"][0]
	refreshToken := r.Header["Refreshtoken"][0]
	res = refreshTokens(accessToken, refreshToken, true)
	result.ReturnJSON(w, &res)

}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	var res result.ResultInfo
	if r.Header["Accesstoken"] == nil || r.Header["Refreshtoken"] == nil {
		res = result.SetErrorResult(`Отсутствуют токены в хедере`)
		result.ReturnJSON(w, &res)
		return
	}
	accessToken := r.Header["Accesstoken"][0]
	refreshToken := r.Header["Refreshtoken"][0]
	res = refreshTokens(accessToken, refreshToken, false)
	result.ReturnJSON(w, &res)
}

func DeleteAllHandler(w http.ResponseWriter, r *http.Request) {
	var res result.ResultInfo
	vars := r.URL.Query()
	if len(vars["guid"]) == 0 {
		res = result.SetErrorResult(`Неверный параметр GUID`)
		result.ReturnJSON(w, &res)
		return
	}
	guid := vars["guid"][0]
	res = deleteAll(guid)
	result.ReturnJSON(w, &res)
}

func createLogin(guid string) (res result.ResultInfo) {
	db := config.GetConnection()
	accessString, err := createAccessToken(guid)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(result.UnknownError)
		return
	}
	refreshString, err := createRefreshToken(guid)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(result.UnknownError)
		return
	}
	query := `INSERT INTO data (guid, access_token, refresh_token, is_active) VALUES ($1, $2, $3, 1)`
	params := []any{guid, accessString, refreshString}
	_, err = db.Exec(query, params...)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(result.UnknownError)
		return
	}
	res.Done = true
	res.Items = map[string]interface{}{"access_token": accessString, "refresh_token": base64.StdEncoding.EncodeToString([]byte(refreshString))}
	return
}

func refreshTokens(accessToken string, refreshToken string, isFull bool) (res result.ResultInfo) {
	db := config.GetConnection()
	query := `SELECT guid, refresh_token FROM data WHERE access_token = $1 AND is_active = 1`
	params := []any{accessToken}
	rows, err := db.Query(query, params...)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(result.UnknownError)
		return
	}
	foundRefresh := false
	var refreshTokenDB string
	var guid string
	for rows.Next() {
		err := rows.Scan(&guid, &refreshTokenDB)
		if err != nil {
			result.ErrorServer(nil, err)
			res = result.SetErrorResult(result.UnknownError)
			rows.Close()
			return
		}
		foundRefresh = checkRefreshToken(refreshTokenDB, refreshToken)
		if foundRefresh {
			break
		}
	}
	rows.Close()
	if !foundRefresh {
		res = result.SetErrorResult("Неверная пара токенов")
		return
	}
	tx, err := db.Begin()
	if err != nil {
		result.ErrorServer(nil, err)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()
	query = `UPDATE data SET is_active = 0 WHERE access_token = $1 AND refresh_token = $2 AND guid = $3`
	params = []any{accessToken, refreshTokenDB, guid}
	//_, err = db.Exec(query, params...)
	_, err = tx.Exec(query, params...)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(`Внутренняя ошибка`)
		return
	}
	if isFull {
		accessString, err := createAccessToken(guid)
		if err != nil {
			result.ErrorServer(nil, err)
			res = result.SetErrorResult(result.UnknownError)
			return
		}
		refreshString, err := createRefreshToken(guid)
		if err != nil {
			result.ErrorServer(nil, err)
			res = result.SetErrorResult(result.UnknownError)
			return
		}
		query = `INSERT INTO data (guid, access_token, refresh_token, is_active) VALUES ($1, $2, $3, 1)`
		params = []any{guid, accessString, refreshString}
		//_, err = db.Exec(query, params...)
		_, err = tx.Exec(query, params...)
		if err != nil {
			result.ErrorServer(nil, err)
			res = result.SetErrorResult(result.UnknownError)
			return
		}
		res.Items = map[string]interface{}{"access_token": accessString, "refresh_token": base64.StdEncoding.EncodeToString([]byte(refreshString))}
	}
	if err = tx.Commit(); err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(`Внутренняя ошибка`)
		return
	}
	res.Done = true
	return
}

func deleteAll(guid string) (res result.ResultInfo) {
	db := config.GetConnection()
	query := `UPDATE data SET is_active = 0 WHERE guid = $1`
	params := []any{guid}
	_, err := db.Exec(query, params...)
	if err != nil {
		result.ErrorServer(nil, err)
		res = result.SetErrorResult(result.UnknownError)
		return
	}
	res.Done = true
	return
}

func createAccessToken(guid string) (string, error) {
	var secretKey = []byte("hello")
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "username"
	tokenString, err := token.SignedString(secretKey)
	return tokenString, err
}

func createRefreshToken(guid string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(guid+strconv.Itoa(int(time.Now().UnixNano()))), 14)
	return string(hash), err
}

func checkRefreshToken(fromDB string, fromHeader string) bool {
	return base64.StdEncoding.EncodeToString([]byte(fromDB)) == fromHeader
}
