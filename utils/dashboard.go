package utils

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
)

func (app *application) supplierDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/supplier/dashboard" && r.URL.Path != "/templates/supplier-dashboard.html" {
		http.NotFound(w, r)
		return
	}
	user, ok := app.requireSupplierAccount(w, r)
	if !ok {
		return
	}

	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create dashboard CSRF token: %v", err)
		http.Error(w, "Unable to load your dashboard.", http.StatusInternalServerError)
		return
	}
	displayName := user.BusinessName
	if displayName == "" {
		displayName = user.Name
	}
	var productCount int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM products WHERE supplier_id = ?", user.ID).Scan(&productCount); err != nil {
		log.Printf("count products for supplier %d: %v", user.ID, err)
		http.Error(w, "Unable to load your dashboard.", http.StatusInternalServerError)
		return
	}
	app.renderTemplate(w, "supplier-dashboard.html", pageData{
		CSRFToken:    token,
		Name:         displayName,
		BusinessName: user.BusinessName,
		ProductCount: productCount,
	})
}

func (app *application) requireSupplierAccount(w http.ResponseWriter, r *http.Request) (account, bool) {
	user, err := app.currentAccount(r)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, http.ErrNoCookie) {
			http.Redirect(w, r, "/templates/login.html", http.StatusSeeOther)
			return account{}, false
		}
		log.Printf("load supplier dashboard account: %v", err)
		http.Error(w, "Unable to load your dashboard.", http.StatusInternalServerError)
		return account{}, false
	}
	if user.Role != "supplier" {
		http.Error(w, "This page is available to supplier accounts only.", http.StatusForbidden)
		return account{}, false
	}
	return user, true
}
func (app *application) logout(w http.ResponseWriter, r *http.Request) {
	if !app.parsePost(w, r) {
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			log.Printf("read logout session cookie: %v", err)
			http.Error(w, "Unable to sign out.", http.StatusInternalServerError)
			return
		}
	} else if _, err := app.db.Exec("DELETE FROM sessions WHERE token_hash = ?", hashToken(cookie.Value)); err != nil {
		log.Printf("delete logout session: %v", err)
		http.Error(w, "Unable to sign out.", http.StatusInternalServerError)
		return
	}
	app.clearCookie(w, sessionCookieName)
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}
