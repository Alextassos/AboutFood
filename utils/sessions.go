package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func (app *application) createSession(w http.ResponseWriter, accountID int64) error {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	expiresAt := time.Now().UTC().Add(sessionDuration)
	if _, err := app.db.Exec(
		"INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)",
		hashToken(token), accountID, expiresAt.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}
func (app *application) currentAccount(r *http.Request) (account, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return account{}, err
	}
	var user account
	err = app.db.QueryRow(`
SELECT accounts.id, accounts.name, accounts.business_name, accounts.email, accounts.phone,
       accounts.category, accounts.role, accounts.status
FROM sessions
JOIN accounts ON accounts.id = sessions.account_id
WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  AND NOT EXISTS (
      SELECT 1 FROM blocked_accounts WHERE blocked_accounts.account_id = accounts.id
  )`,
		hashToken(cookie.Value), time.Now().UTC().Format(time.RFC3339)).Scan(
		&user.ID, &user.Name, &user.BusinessName, &user.Email, &user.Phone, &user.Category, &user.Role, &user.Status)
	if err != nil {
		return account{}, err
	}
	return user, nil
}
func (app *application) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}
func hashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
