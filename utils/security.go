package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

func (app *application) issueCSRF(w http.ResponseWriter) (string, error) {
	randomToken := make([]byte, 32)
	if _, err := rand.Read(randomToken); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, app.csrfSecret)
	_, _ = mac.Write(randomToken)
	token := append(randomToken, mac.Sum(nil)...)
	encoded := base64.RawURLEncoding.EncodeToString(token)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	return encoded, nil
}
func (app *application) validateCSRF(r *http.Request) bool {
	if r.Header.Get("Origin") != "" && !sameOrigin(r) {
		return false
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	formToken := r.FormValue("csrf_token")
	if formToken == "" || !hmac.Equal([]byte(cookie.Value), []byte(formToken)) {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(formToken)
	if err != nil || len(token) != 64 {
		return false
	}
	mac := hmac.New(sha256.New, app.csrfSecret)
	_, _ = mac.Write(token[:32])
	return hmac.Equal(token[32:], mac.Sum(nil))
}
func sameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.User != nil || origin.Host == "" ||
		(origin.Scheme != "https" && origin.Scheme != "http") ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	return strings.EqualFold(origin.Host, r.Host)
}
func (app *application) parsePost(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The submitted form is invalid or too large.", http.StatusBadRequest)
		return false
	}
	if !app.validateCSRF(r) {
		http.Error(w, "Your form expired or could not be verified. Reload the page and try again.", http.StatusForbidden)
		return false
	}
	return true
}
