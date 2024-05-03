package authentiksso

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

func New(clientId, clientSecret, baseURL string) *AuthentikClient {
	return &AuthentikClient{
		BaseURL:      baseURL,
		ClentId:      clientId,
		ClientSecret: clientSecret,
	}
}

type AuthentikClient struct {
	BaseURL      string
	ClentId      string
	ClientSecret string
}

func (c *AuthentikClient) OAuth2Url(scope []string, redirectUri string) string {
	return c.BaseURL + "/application/o/authorize/?client_id=" + c.ClentId + "&scope=" + strings.Join(scope, " ") + "&redirect_uri=" + redirectUri
}

type Token struct {
	AccessToken string `json:"access_token"`
	Idtoken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (c *AuthentikClient) RetriveToken(code string, redirectUri string) (Token, error) {
	var token Token
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("client_id", c.ClentId)
	writer.WriteField("client_secret", c.ClientSecret)
	writer.WriteField("code", code)
	writer.WriteField("redirect_uri", redirectUri)
	writer.WriteField("grant_type", "authorization_code")
	defer writer.Close()
	r, _ := http.NewRequest("POST", c.BaseURL+"/application/o/token/", body)
	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return token, err
	}
	if resp.StatusCode != 200 {
		var tokenError TokenError
		json.Unmarshal(buf, &tokenError)
		return token, errors.New(tokenError.ErrorDescription)
	}
	json.Unmarshal(buf, &token)
	return token, nil
}

func (c *AuthentikClient) GetUserInfo(accessToken string) (string, error) {
	return "", nil
}
