package utils

import (
	"log"
	"net/http"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

func (app *application) register(w http.ResponseWriter, r *http.Request) {
	app.handleRegistration(w, r, "")
}
func (app *application) registerSupplier(w http.ResponseWriter, r *http.Request) {
	app.handleRegistration(w, r, "supplier")
}
func (app *application) handleRegistration(w http.ResponseWriter, r *http.Request, forcedRole string) {
	if !app.parsePost(w, r) {
		return
	}

	name := strings.TrimSpace(r.PostForm.Get("name"))
	businessName := strings.TrimSpace(r.PostForm.Get("business_name"))
	email := strings.ToLower(strings.TrimSpace(r.PostForm.Get("email")))
	password := r.PostForm.Get("password")
	role := strings.TrimSpace(r.PostForm.Get("role"))
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	category := strings.TrimSpace(r.PostForm.Get("category"))
	if forcedRole != "" {
		role = forcedRole
	} else if role == "" {
		role = "customer"
	}

	var validationError string
	switch {
	case len(name) < 2 || len(name) > 120:
		validationError = "Enter a name between 2 and 120 characters."
	case len(email) > 254 || !validEmail(email):
		validationError = "Enter a valid email address."
	case role != "customer" && role != "supplier":
		validationError = "The selected account type is not supported."
	case role == "supplier" && len(businessName) < 2:
		validationError = "Supplier accounts need a business name. Please use the supplier registration form."
	case len(businessName) > 160 || len(phone) > 40:
		validationError = "One of the business details is too long."
	case role == "supplier" && !validCategory(category):
		validationError = "Select a valid product category."
	case !validPassword(password):
		validationError = "Use a password with at least 8 characters, one uppercase letter, and one symbol (maximum 72 bytes)."
	case role == "supplier" && r.PostForm.Get("terms_accepted") != "yes":
		validationError = "You must accept the Terms & Conditions to register."
	}
	if validationError != "" {
		app.renderRegistrationError(w, r, role, validationError, pageData{
			Name: name, BusinessName: businessName, Email: email, Category: category,
		})
		return
	}

	var emailExists bool
	if err := app.db.QueryRow("SELECT EXISTS (SELECT 1 FROM accounts WHERE lower(email) = ?)", email).Scan(&emailExists); err != nil {
		log.Printf("check account email availability: %v", err)
		http.Error(w, "Unable to create your account right now.", http.StatusInternalServerError)
		return
	}
	if emailExists {
		app.renderRegistrationError(w, r, role, "An account with this email already exists. Try signing in instead.", pageData{
			Name: name, BusinessName: businessName, Email: email, Category: category,
		})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("hash account password: %v", err)
		http.Error(w, "Unable to create your account right now.", http.StatusInternalServerError)
		return
	}

	status := "active"
	result, err := app.db.Exec(`
INSERT INTO accounts (name, business_name, email, phone, category, role, status, password_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, businessName, email, phone, category, role, status, string(passwordHash))
	if err != nil {
		if isUniqueConstraint(err) {
			app.renderRegistrationError(w, r, role, "An account with this email already exists. Try signing in instead.", pageData{
				Name: name, BusinessName: businessName, Email: email, Category: category,
			})
			return
		}
		log.Printf("save account registration: %v", err)
		http.Error(w, "Unable to create your account right now.", http.StatusInternalServerError)
		return
	}

	accountID, err := result.LastInsertId()
	if err != nil {
		log.Printf("read new account ID: %v", err)
		http.Error(w, "Your account was created, but we could not start a session. Please sign in.", http.StatusInternalServerError)
		return
	}
	if err := app.createSession(w, accountID); err != nil {
		log.Printf("create account session: %v", err)
		http.Error(w, "Your account was created, but we could not start a session. Please sign in.", http.StatusInternalServerError)
		return
	}
	if role == "supplier" {
		http.Redirect(w, r, "/supplier/dashboard", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}
func (app *application) renderRegistrationError(w http.ResponseWriter, r *http.Request, role, message string, data pageData) {
	data.Error = message
	if role == "supplier" {
		token, err := app.issueCSRF(w)
		if err != nil {
			log.Printf("refresh supplier registration CSRF token: %v", err)
			http.Error(w, "Unable to reload the registration form. Please try again.", http.StatusInternalServerError)
			return
		}
		data.CSRFToken = token
		app.renderTemplateStatus(w, "supplier-register.html", data, http.StatusUnprocessableEntity)
		return
	}
	data.ShowSignup = true
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("refresh account registration CSRF token: %v", err)
		http.Error(w, "Unable to reload the registration form. Please try again.", http.StatusInternalServerError)
		return
	}
	data.CSRFToken = token
	app.renderTemplateStatus(w, "auth.html", data, http.StatusUnprocessableEntity)
}
func validEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && strings.Contains(value, "@")
}
func validPassword(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 8 || len(value) > 72 {
		return false
	}

	hasUppercase := false
	hasSymbol := false
	for _, character := range value {
		hasUppercase = hasUppercase || unicode.IsUpper(character)
		hasSymbol = hasSymbol || unicode.IsPunct(character) || unicode.IsSymbol(character)
	}
	return hasUppercase && hasSymbol
}
func validCategory(value string) bool {
	switch value {
	case "olive-oil", "seafood", "wine", "dairy", "produce", "other":
		return true
	default:
		return false
	}
}

func categoryLabel(value string) string {
	switch value {
	case "olive-oil":
		return "Olive oil"
	case "seafood":
		return "Seafood"
	case "wine":
		return "Wine"
	case "dairy":
		return "Dairy"
	case "produce":
		return "Produce"
	default:
		return "Other"
	}
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
