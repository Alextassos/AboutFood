package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func configureAdmin() (string, string, []byte, error) {
	adminPath := strings.TrimSpace(os.Getenv("ADMIN_PATH"))
	email := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	password := os.Getenv("ADMIN_PASSWORD")
	if adminPath == "" {
		if email == "" && password == "" {
			return "", "", nil, nil
		}
		return "", "", nil, errors.New("ADMIN_PATH must be set when administrator credentials are configured")
	}
	if !validAdminPath(adminPath) {
		return "", "", nil, errors.New("ADMIN_PATH must be a private single-segment path with at least 24 characters after the leading slash")
	}
	if email == "" && password == "" {
		return adminPath, "", nil, nil
	}
	if !validEmail(email) {
		return "", "", nil, errors.New("ADMIN_EMAIL must be a valid email address")
	}
	if len(password) < 16 || len(password) > 72 {
		return "", "", nil, errors.New("ADMIN_PASSWORD must be between 16 and 72 bytes")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", nil, fmt.Errorf("hash admin password: %w", err)
	}
	return adminPath, email, passwordHash, nil
}

func validAdminPath(value string) bool {
	if !strings.HasPrefix(value, "/") || len(value) < 25 || strings.Contains(value[1:], "/") {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func (app *application) adminLoginPage(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		AdminConfigured: app.adminEmail != "" && len(app.adminHash) > 0,
		AdminBase:       app.adminPath,
	}
	if app.adminPath == "" {
		http.NotFound(w, r)
		return
	}
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create admin login CSRF token: %v", err)
		http.Error(w, "Unable to load admin sign-in.", http.StatusInternalServerError)
		return
	}
	data.CSRFToken = token
	app.renderTemplate(w, "admin-login.html", data)
}

func (app *application) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !app.parsePost(w, r) {
		return
	}
	if app.adminEmail == "" || len(app.adminHash) == 0 {
		http.Error(w, "Admin access is not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD, then restart the server.", http.StatusServiceUnavailable)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostForm.Get("email")))
	password := r.PostForm.Get("password")
	passwordErr := bcrypt.CompareHashAndPassword(app.adminHash, []byte(password))
	if email != app.adminEmail || passwordErr != nil {
		app.renderAdminLoginError(w)
		return
	}

	if err := app.createAdminSession(w); err != nil {
		log.Printf("create admin session: %v", err)
		http.Error(w, "Unable to sign in as administrator.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, app.adminPath+"/accounts", http.StatusSeeOther)
}

func (app *application) renderAdminLoginError(w http.ResponseWriter) {
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("refresh admin login CSRF token: %v", err)
		http.Error(w, "Unable to reload admin sign-in.", http.StatusInternalServerError)
		return
	}
	app.renderTemplateStatus(w, "admin-login.html", pageData{
		CSRFToken:       token,
		Error:           "The email or password is incorrect.",
		AdminConfigured: true,
		AdminBase:       app.adminPath,
	}, http.StatusUnauthorized)
}

func (app *application) createAdminSession(w http.ResponseWriter) error {
	randomToken := make([]byte, 32)
	if _, err := rand.Read(randomToken); err != nil {
		return fmt.Errorf("generate admin session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(randomToken)
	expiresAt := time.Now().UTC().Add(sessionDuration)
	if _, err := app.db.Exec(
		"INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)",
		hashToken(token), expiresAt.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("save admin session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (app *application) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if app.adminPath == "" || app.adminEmail == "" || len(app.adminHash) == 0 {
		http.Error(w, "Admin access is not configured.", http.StatusServiceUnavailable)
		return false
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			log.Printf("read admin session cookie: %v", err)
			http.Error(w, "Unable to verify administrator session.", http.StatusInternalServerError)
			return false
		}
		http.Redirect(w, r, app.adminPath+"/login", http.StatusSeeOther)
		return false
	}
	var exists bool
	if err := app.db.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM admin_sessions WHERE token_hash = ? AND expires_at > ?)",
		hashToken(cookie.Value), time.Now().UTC().Format(time.RFC3339)).Scan(&exists); err != nil {
		log.Printf("verify admin session: %v", err)
		http.Error(w, "Unable to verify administrator session.", http.StatusInternalServerError)
		return false
	}
	if !exists {
		app.clearCookie(w, adminCookieName)
		http.Redirect(w, r, app.adminPath+"/login", http.StatusSeeOther)
		return false
	}
	return true
}

func (app *application) adminAccountsPage(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	searchPattern := "%" + escapeLike(query) + "%"
	rows, err := app.db.Query(`
SELECT accounts.id, accounts.name, accounts.business_name, accounts.email,
       accounts.phone, accounts.category, accounts.role,
       EXISTS (SELECT 1 FROM blocked_accounts WHERE blocked_accounts.account_id = accounts.id),
       accounts.created_at
FROM accounts
WHERE ? = '' OR lower(accounts.name) LIKE lower(?) ESCAPE '\'
   OR lower(accounts.business_name) LIKE lower(?) ESCAPE '\'
   OR lower(accounts.email) LIKE lower(?) ESCAPE '\'
   OR lower(accounts.phone) LIKE lower(?) ESCAPE '\'
ORDER BY accounts.created_at DESC, accounts.id DESC`,
		query, searchPattern, searchPattern, searchPattern, searchPattern)
	if err != nil {
		log.Printf("search admin accounts: %v", err)
		http.Error(w, "Unable to load accounts.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	accounts := make([]adminAccount, 0)
	for rows.Next() {
		var user adminAccount
		var blocked int
		if err := rows.Scan(
			&user.ID, &user.Name, &user.BusinessName, &user.Email, &user.Phone,
			&user.Category, &user.Role, &blocked, &user.CreatedAt,
		); err != nil {
			log.Printf("read admin account: %v", err)
			http.Error(w, "Unable to load accounts.", http.StatusInternalServerError)
			return
		}
		user.Blocked = blocked != 0
		accounts = append(accounts, user)
	}
	if err := rows.Err(); err != nil {
		log.Printf("iterate admin accounts: %v", err)
		http.Error(w, "Unable to load accounts.", http.StatusInternalServerError)
		return
	}
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create admin accounts CSRF token: %v", err)
		http.Error(w, "Unable to load accounts.", http.StatusInternalServerError)
		return
	}
	data := pageData{
		CSRFToken: token,
		Accounts:  accounts,
		Query:     query,
		Notice:    adminNotice(r.URL.Query().Get("notice")),
		AdminBase: app.adminPath,
	}
	app.renderTemplate(w, "admin-accounts.html", data)
}

func adminNotice(value string) string {
	switch value {
	case "blocked":
		return "Account blocked. Its sessions are now disabled."
	case "unblocked":
		return "Account unblocked."
	case "deleted":
		return "Account deleted, including its products and sessions."
	default:
		return ""
	}
}

func (app *application) blockAccount(w http.ResponseWriter, r *http.Request) {
	app.changeAccountBlock(w, r, true)
}

func (app *application) unblockAccount(w http.ResponseWriter, r *http.Request) {
	app.changeAccountBlock(w, r, false)
}

func (app *application) changeAccountBlock(w http.ResponseWriter, r *http.Request, block bool) {
	if !app.requireAdmin(w, r) || !app.parsePost(w, r) {
		return
	}
	accountID, ok := adminAccountID(w, r)
	if !ok {
		return
	}
	var exists bool
	if err := app.db.QueryRow("SELECT EXISTS (SELECT 1 FROM accounts WHERE id = ?)", accountID).Scan(&exists); err != nil {
		log.Printf("check account %d before changing block status: %v", accountID, err)
		http.Error(w, "Unable to update account status.", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	var err error
	notice := "unblocked"
	if block {
		_, err = app.db.Exec(
			"INSERT INTO blocked_accounts (account_id) VALUES (?) ON CONFLICT(account_id) DO NOTHING",
			accountID)
		notice = "blocked"
	} else {
		_, err = app.db.Exec("DELETE FROM blocked_accounts WHERE account_id = ?", accountID)
	}
	if err != nil {
		log.Printf("change block status for account %d: %v", accountID, err)
		http.Error(w, "Unable to update account status.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, app.adminAccountsURL(r, notice), http.StatusSeeOther)
}

func (app *application) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) || !app.parsePost(w, r) {
		return
	}
	accountID, ok := adminAccountID(w, r)
	if !ok {
		return
	}
	result, err := app.db.Exec("DELETE FROM accounts WHERE id = ?", accountID)
	if err != nil {
		log.Printf("delete account %d: %v", accountID, err)
		http.Error(w, "Unable to delete account.", http.StatusInternalServerError)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		log.Printf("check deleted account %d: %v", accountID, err)
		http.Error(w, "Unable to delete account.", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, app.adminAccountsURL(r, "deleted"), http.StatusSeeOther)
}

func adminAccountID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	accountID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || accountID < 1 {
		http.Error(w, "Invalid account ID.", http.StatusBadRequest)
		return 0, false
	}
	return accountID, true
}

func (app *application) adminAccountsURL(r *http.Request, notice string) string {
	values := url.Values{}
	if query := strings.TrimSpace(r.PostForm.Get("q")); query != "" {
		values.Set("q", query)
	}
	values.Set("notice", notice)
	return app.adminPath + "/accounts?" + values.Encode()
}

func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

func (app *application) adminLogout(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) || !app.parsePost(w, r) {
		return
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		log.Printf("read admin logout cookie: %v", err)
		http.Error(w, "Unable to sign out.", http.StatusInternalServerError)
		return
	}
	if _, err := app.db.Exec("DELETE FROM admin_sessions WHERE token_hash = ?", hashToken(cookie.Value)); err != nil {
		log.Printf("delete admin session: %v", err)
		http.Error(w, "Unable to sign out.", http.StatusInternalServerError)
		return
	}
	app.clearCookie(w, adminCookieName)
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}
