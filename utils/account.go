package utils

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
)

func (app *application) accountPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/account" && r.URL.Path != "/templates/account.html" {
		http.NotFound(w, r)
		return
	}
	user, err := app.currentAccount(r)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			http.Redirect(w, r, "/templates/login.html", http.StatusSeeOther)
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			app.clearCookie(w, sessionCookieName)
			http.Redirect(w, r, "/templates/login.html", http.StatusSeeOther)
			return
		}
		log.Printf("load account profile: %v", err)
		http.Error(w, "Unable to load your account.", http.StatusInternalServerError)
		return
	}
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create account CSRF token: %v", err)
		http.Error(w, "Unable to load your account.", http.StatusInternalServerError)
		return
	}
	app.renderTemplate(w, "account.html", pageData{
		CSRFToken:    token,
		Name:         user.Name,
		BusinessName: user.BusinessName,
		Email:        user.Email,
		Phone:        user.Phone,
		Category:     user.Category,
		Role:         user.Role,
	})
}
