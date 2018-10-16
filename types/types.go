package types

import "net/http"

type GithubRequestBody struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	State        string `json:"state"`
}

type GithubResponseBody struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type GithubUserDataResponse struct {
	Username string `json:"login"`
	ID       string `json:"id"`
	Icon     string `json:"avatar_url"`
	Email    string `json:"email"`
}

type AuthResponse struct {
	Name string `json:"name"`
	Icon string `json:"icon"`
}

type ConfigFile struct {
	ID       string `yaml:"ID"`
	Secret   string `yaml:"SECRET"`
	TokenKey string `yaml:"TOKEN_KEY"`
}

// PortMapping include messages to be used
type PortMapping struct {
	Port       int
	DomainName string
	Command    string
}

// RequestCommand stores command and jwt in every ws message
type RequestCommand struct {
	Command     string
	JWT         string
	Project     string
	username    string
	projectType int
}

// ErrorHandler is error handler for http
type ErrorHandler func(w http.ResponseWriter, r *http.Request) error
