package utils

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

func Run() {
	root, err := os.Getwd()
	if err != nil {
		log.Fatalf("get working directory: %v", err)
	}

	databasePath := os.Getenv("DATABASE_PATH")
	if databasePath == "" {
		databasePath = filepath.Join(root, "data", "aboutfood.db")
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		log.Fatalf("create database directory: %v", err)
	}

	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`); err != nil {
		log.Fatalf("configure database: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		log.Fatalf("initialize database: %v", err)
	}

	adminPath, adminEmail, adminHash, err := configureAdmin()
	if err != nil {
		log.Fatalf("configure administrator access: %v", err)
	}
	if adminEmail == "" {
		log.Print("Administrator credentials are not set; administrator access is disabled")
	}

	secret, err := csrfSecret()
	if err != nil {
		log.Fatalf("configure CSRF protection: %v", err)
	}
	secureCookie, err := cookieSecureSetting()
	if err != nil {
		log.Fatalf("configure cookies: %v", err)
	}
	if os.Getenv("APP_ENV") == "production" {
		if os.Getenv("CSRF_SECRET") == "" {
			log.Fatal("CSRF_SECRET must be set in production")
		}
		if !secureCookie {
			log.Fatal("COOKIE_SECURE must be true in production")
		}
	}

	app := &application{
		db:           db,
		root:         root,
		csrfSecret:   secret,
		secureCookie: secureCookie,
		adminPath:    adminPath,
		adminEmail:   adminEmail,
		adminHash:    adminHash,
		mux:          http.NewServeMux(),
	}
	app.routes()

	address, err := listenAddress()
	if err != nil {
		log.Fatalf("configure server address: %v", err)
	}
	server := &http.Server{
		Addr:              address,
		Handler:           securityHeaders(app.mux, secureCookie),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("About Food server listening on %s", address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}
func (app *application) routes() {
	app.mux.HandleFunc("GET /{$}", app.home)
	app.mux.HandleFunc("GET /index.html", app.home)
	app.mux.Handle("GET /style.css", http.FileServer(http.Dir(app.root)))
	app.mux.HandleFunc("GET /templates/supplier-register.html", app.supplierRegistrationPage)
	app.mux.HandleFunc("GET /templates/products.html", app.publicProductsPage)
	app.mux.HandleFunc("GET /templates/about.html", app.publicInfoPage)
	app.mux.HandleFunc("GET /templates/suppliers.html", app.publicInfoPage)
	app.mux.HandleFunc("GET /templates/login.html", app.loginPage)
	app.mux.HandleFunc("GET /templates/auth.html", app.authPage)
	app.mux.HandleFunc("GET /forgot", app.forgotPage)
	app.mux.HandleFunc("GET /templates/forgot.html", app.forgotPage)
	app.mux.HandleFunc("GET /templates/account.html", app.accountPage)
	app.mux.HandleFunc("GET /templates/supplier-products.html", app.supplierProductsPage)
	if app.adminPath != "" {
		app.mux.HandleFunc("GET "+app.adminPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, app.adminPath+"/accounts", http.StatusSeeOther)
		})
		app.mux.HandleFunc("GET "+app.adminPath+"/login", app.adminLoginPage)
		app.mux.HandleFunc("POST "+app.adminPath+"/login", app.adminLogin)
		app.mux.HandleFunc("POST "+app.adminPath+"/logout", app.adminLogout)
		app.mux.HandleFunc("GET "+app.adminPath+"/accounts", app.adminAccountsPage)
		app.mux.HandleFunc("POST "+app.adminPath+"/accounts/{id}/block", app.blockAccount)
		app.mux.HandleFunc("POST "+app.adminPath+"/accounts/{id}/unblock", app.unblockAccount)
		app.mux.HandleFunc("POST "+app.adminPath+"/accounts/{id}/delete", app.deleteAccount)
	}
	app.mux.HandleFunc("POST /register", app.register)
	app.mux.HandleFunc("POST /register/supplier", app.registerSupplier)
	app.mux.HandleFunc("POST /login", app.login)
	app.mux.HandleFunc("POST /logout", app.logout)
	app.mux.HandleFunc("GET /account", app.accountPage)
	app.mux.HandleFunc("GET /supplier/dashboard", app.supplierDashboard)
	app.mux.HandleFunc("GET /templates/supplier-dashboard.html", app.supplierDashboard)
	app.mux.HandleFunc("GET /supplier/products", app.supplierProductsPage)
	app.mux.HandleFunc("POST /supplier/products", app.createSupplierProduct)
	app.mux.HandleFunc("POST /supplier/products/{id}/update", app.updateSupplierProduct)
	app.mux.HandleFunc("POST /supplier/products/{id}/delete", app.deleteSupplierProduct)

	app.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(app.root, "static")))))
	app.mux.Handle("/photo/", http.StripPrefix("/photo/", http.FileServer(http.Dir(filepath.Join(app.root, "photo")))))
	app.mux.Handle("/templates/", http.StripPrefix("/templates/", http.FileServer(http.Dir(filepath.Join(app.root, "templates")))))
}
func securityHeaders(next http.Handler, secureCookie bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if secureCookie {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
func (app *application) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	data := pageData{}
	user, err := app.currentAccount(r)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		if errors.Is(err, sql.ErrNoRows) {
			app.clearCookie(w, sessionCookieName)
		} else {
			log.Printf("load account for homepage: %v", err)
			http.Error(w, "Unable to load the homepage.", http.StatusInternalServerError)
			return
		}
	}
	if err == nil {
		data.Authenticated = true
		data.Role = user.Role
		data.CSRFToken, err = app.issueCSRF(w)
		if err != nil {
			log.Printf("create homepage CSRF token: %v", err)
			http.Error(w, "Unable to load the homepage.", http.StatusInternalServerError)
			return
		}
	}
	if err := renderTemplatePath(w, filepath.Join(app.root, "index.html"), "index.html", data, http.StatusOK); err != nil {
		log.Printf("render homepage: %v", err)
	}
}

func (app *application) publicInfoPage(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	if (filename != "about.html" && filename != "suppliers.html") ||
		r.URL.Path != "/templates/"+filename {
		http.NotFound(w, r)
		return
	}

	data := pageData{}
	user, err := app.currentAccount(r)
	if err == nil {
		data.Authenticated = true
		data.Role = user.Role
		data.CSRFToken, err = app.issueCSRF(w)
		if err != nil {
			log.Printf("create public page logout CSRF token: %v", err)
			http.Error(w, "Unable to load this page.", http.StatusInternalServerError)
			return
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		app.clearCookie(w, sessionCookieName)
	} else if !errors.Is(err, http.ErrNoCookie) {
		log.Printf("load public page account navigation: %v", err)
		http.Error(w, "Unable to load this page.", http.StatusInternalServerError)
		return
	}
	if filename == "suppliers.html" {
		data.Suppliers, err = app.marketplaceSuppliers()
		if err != nil {
			log.Printf("load marketplace suppliers: %v", err)
			http.Error(w, "Unable to load marketplace suppliers.", http.StatusInternalServerError)
			return
		}
	}
	app.renderTemplate(w, filename, data)
}
