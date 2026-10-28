package utils

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	if !app.parsePost(w, r) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostForm.Get("email")))
	password := r.PostForm.Get("password")
	var user account
	var passwordHash string
	var blocked bool
	err := app.db.QueryRow(`
SELECT id, name, business_name, email, phone, category, role, status, password_hash
FROM accounts WHERE email = ?`, email).Scan(
		&user.ID, &user.Name, &user.BusinessName, &user.Email, &user.Phone, &user.Category, &user.Role, &user.Status, &passwordHash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("look up account for login: %v", err)
			http.Error(w, "Unable to sign in right now.", http.StatusInternalServerError)
			return
		}
		app.renderLoginError(w, "The email or password is incorrect.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		app.renderLoginError(w, "The email or password is incorrect.")
		return
	}
	if err := app.db.QueryRow("SELECT EXISTS (SELECT 1 FROM blocked_accounts WHERE account_id = ?)", user.ID).Scan(&blocked); err != nil {
		log.Printf("check blocked account at login: %v", err)
		http.Error(w, "Unable to sign in right now.", http.StatusInternalServerError)
		return
	}
	if blocked {
		app.renderLoginError(w, "This account is currently blocked. Please contact About Food support.")
		return
	}
	if err := app.createSession(w, user.ID); err != nil {
		log.Printf("create login session: %v", err)
		http.Error(w, "Unable to sign in right now.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}
func (app *application) renderLoginError(w http.ResponseWriter, message string) {
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("refresh login CSRF token: %v", err)
		http.Error(w, "Unable to reload the sign-in form. Please try again.", http.StatusInternalServerError)
		return
	}
	app.renderTemplateStatus(w, "login.html", pageData{CSRFToken: token, Error: message}, http.StatusUnauthorized)
}
