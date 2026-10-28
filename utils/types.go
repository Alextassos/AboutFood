package utils

import (
	"database/sql"
	"net/http"
	"time"
)

const (
	sessionCookieName = "aboutfood_session"
	adminCookieName   = "aboutfood_admin"
	csrfCookieName    = "aboutfood_csrf"
	sessionDuration   = 12 * time.Hour
	maxFormBytes      = 16 << 10
)

type application struct {
	db           *sql.DB
	root         string
	csrfSecret   []byte
	secureCookie bool
	adminPath    string
	adminEmail   string
	adminHash    []byte
	mux          *http.ServeMux
}

type pageData struct {
	CSRFToken       string
	Error           string
	Notice          string
	Name            string
	BusinessName    string
	Email           string
	Phone           string
	Category        string
	Query           string
	AdminBase       string
	ShowSignup      bool
	Role            string
	Authenticated   bool
	AdminConfigured bool
	Products        []product
	Suppliers       []supplier
	Accounts        []adminAccount
	ProductCount    int
}

type account struct {
	ID           int64
	Name         string
	BusinessName string
	Email        string
	Phone        string
	Category     string
	Role         string
	Status       string
}

type product struct {
	ID            int64
	Name          string
	Description   string
	Category      string
	CategoryLabel string
	Price         float64
	Unit          string
	Active        bool
	SupplierName  string
}

type supplier struct {
	BusinessName  string
	Category      string
	CategoryLabel string
	ProductCount  int
}

type adminAccount struct {
	ID           int64
	Name         string
	BusinessName string
	Email        string
	Phone        string
	Category     string
	Role         string
	Blocked      bool
	CreatedAt    string
}
