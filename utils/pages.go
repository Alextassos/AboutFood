package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func (app *application) supplierRegistrationPage(w http.ResponseWriter, r *http.Request) {
	app.renderForm(w, r, "supplier-register.html", pageData{})
}
func (app *application) loginPage(w http.ResponseWriter, r *http.Request) {
	app.renderForm(w, r, "login.html", pageData{})
}
func (app *application) authPage(w http.ResponseWriter, r *http.Request) {
	app.renderForm(w, r, "auth.html", pageData{})
}
func (app *application) forgotPage(w http.ResponseWriter, r *http.Request) {
	app.renderTemplate(w, "forgot.html", pageData{})
}
func (app *application) renderForm(w http.ResponseWriter, r *http.Request, filename string, data pageData) {
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create CSRF token: %v", err)
		http.Error(w, "Unable to load this page. Please try again.", http.StatusInternalServerError)
		return
	}
	data.CSRFToken = token
	app.renderTemplate(w, filename, data)
}
func (app *application) renderTemplate(w http.ResponseWriter, filename string, data any) {
	app.renderTemplateStatus(w, filename, data, http.StatusOK)
}
func (app *application) renderTemplateStatus(w http.ResponseWriter, filename string, data any, status int) error {
	templatePath := filepath.Join(app.root, "templates", filename)
	return renderTemplatePath(w, templatePath, filename, data, status)
}

func renderTemplatePath(w http.ResponseWriter, templatePath, filename string, data any, status int) error {
	page, err := template.ParseFiles(templatePath)
	if err != nil {
		err = fmt.Errorf("parse template %q: %w", filename, err)
		log.Printf("%v", err)
		http.Error(w, "Unable to load this page.", http.StatusInternalServerError)
		return err
	}

	var rendered bytes.Buffer
	if err := page.Execute(&rendered, data); err != nil {
		err = fmt.Errorf("render template %q: %w", filename, err)
		log.Printf("%v", err)
		http.Error(w, "Unable to load this page.", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(rendered.Bytes()); err != nil {
		err = fmt.Errorf("write template %q: %w", filename, err)
		log.Printf("%v", err)
		return err
	}
	return nil
}
