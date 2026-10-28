package utils

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var csrfInputPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func newTestApplication(t *testing.T) *application {
	t.Helper()

	databaseName := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared", databaseName))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	app := &application{
		db:           db,
		root:         "..",
		csrfSecret:   []byte("test-only-csrf-secret-with-at-least-32-bytes"),
		secureCookie: false,
		adminPath:    "/private-admin-test-path-123456789",
		mux:          http.NewServeMux(),
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	app.routes()
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	return app
}

func getCSRFToken(t *testing.T, app *application, path string, sessionCookies ...*http.Cookie) (string, *http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	for _, cookie := range sessionCookies {
		request.AddCookie(cookie)
	}
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", path, recorder.Code, recorder.Body.String())
	}
	match := csrfInputPattern.FindStringSubmatch(recorder.Body.String())
	if len(match) != 2 {
		t.Fatalf("GET %s did not render a CSRF token", path)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			return match[1], cookie
		}
	}
	t.Fatalf("GET %s did not set a CSRF cookie", path)
	return "", nil
}

func postForm(t *testing.T, app *application, path string, values url.Values, csrfToken string, csrfCookie *http.Cookie, sessionCookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	values.Set("csrf_token", csrfToken)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.test")
	request.Host = "example.test"
	request.AddCookie(csrfCookie)
	for _, cookie := range sessionCookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	return recorder
}

func createAccountSession(t *testing.T, app *application, name, businessName, email, role string) (int64, *http.Cookie) {
	t.Helper()
	result, err := app.db.Exec(`
INSERT INTO accounts (name, business_name, email, role, status, password_hash)
VALUES (?, ?, ?, ?, 'active', 'test-hash')`, name, businessName, email, role)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := app.createSession(recorder, accountID); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return accountID, cookie
		}
	}
	t.Fatal("account session did not issue a cookie")
	return 0, nil
}

func TestSupplierRegistrationSignsInWithoutApproval(t *testing.T) {
	app := newTestApplication(t)
	token, cookie := getCSRFToken(t, app, "/templates/supplier-register.html")
	values := url.Values{
		"name":           {"Test Supplier"},
		"business_name":  {"Test Farm"},
		"email":          {"supplier@example.test"},
		"phone":          {"+30 210 000 0000"},
		"category":       {"olive-oil"},
		"password":       {"StrongPass1!"},
		"terms_accepted": {"yes"},
		"role":           {"customer"},
	}
	response := postForm(t, app, "/register/supplier", values, token, cookie)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/supplier/dashboard" {
		t.Fatalf("supplier registration returned %d: %s", response.Code, response.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, responseCookie := range response.Result().Cookies() {
		if responseCookie.Name == sessionCookieName {
			sessionCookie = responseCookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("supplier registration did not issue a session cookie")
	}

	var role, status string
	if err := app.db.QueryRow("SELECT role, status FROM accounts WHERE email = ?", "supplier@example.test").Scan(&role, &status); err != nil {
		t.Fatal(err)
	}
	if role != "supplier" || status != "active" {
		t.Fatalf("registered account has role=%q status=%q; want supplier/active", role, status)
	}
	dashboardRequest := httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	dashboardRequest.AddCookie(sessionCookie)
	dashboard := httptest.NewRecorder()
	app.mux.ServeHTTP(dashboard, dashboardRequest)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "Good morning, Test Farm") {
		t.Fatalf("new supplier dashboard returned %d: %s", dashboard.Code, dashboard.Body.String())
	}
	homepageRequest := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	homepageRequest.AddCookie(sessionCookie)
	homepage := httptest.NewRecorder()
	app.mux.ServeHTTP(homepage, homepageRequest)
	if homepage.Code != http.StatusOK || !strings.Contains(homepage.Body.String(), `<a href="/supplier/dashboard">Supplier dashboard</a>`) {
		t.Fatalf("supplier homepage did not show a dashboard link: %d %s", homepage.Code, homepage.Body.String())
	}
	productsRequest := httptest.NewRequest(http.MethodGet, "/templates/products.html", nil)
	productsRequest.AddCookie(sessionCookie)
	productsPage := httptest.NewRecorder()
	app.mux.ServeHTTP(productsPage, productsRequest)
	if productsPage.Code != http.StatusOK || !strings.Contains(productsPage.Body.String(), `<a href="/supplier/dashboard">Supplier dashboard</a>`) {
		t.Fatalf("supplier marketplace navigation did not show a dashboard link: %d %s", productsPage.Code, productsPage.Body.String())
	}

	token, cookie = getCSRFToken(t, app, "/templates/login.html")
	login := postForm(t, app, "/login", url.Values{
		"email":    {"supplier@example.test"},
		"password": {"StrongPass1!"},
	}, token, cookie)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/index.html" {
		t.Fatalf("supplier login returned %d: %s", login.Code, login.Body.String())
	}
}

func TestSupplierDashboardRequiresActiveSupplierSession(t *testing.T) {
	app := newTestApplication(t)

	for _, path := range []string{"/supplier/dashboard", "/templates/supplier-dashboard.html"} {
		recorder := httptest.NewRecorder()
		app.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/templates/login.html" {
			t.Errorf("unauthenticated GET %s returned %d, Location %q", path, recorder.Code, recorder.Header().Get("Location"))
		}
	}

	token, csrfCookie := getCSRFToken(t, app, "/templates/auth.html")
	registration := postForm(t, app, "/register", url.Values{
		"name":     {"Test Buyer"},
		"email":    {"buyer@example.test"},
		"password": {"StrongPass1!"},
		"role":     {"customer"},
	}, token, csrfCookie)
	if registration.Code != http.StatusSeeOther {
		t.Fatalf("customer registration returned %d: %s", registration.Code, registration.Body.String())
	}
	if registration.Header().Get("Location") != "/index.html" {
		t.Fatalf("buyer registration redirected to %q; want homepage", registration.Header().Get("Location"))
	}

	var sessionCookie *http.Cookie
	for _, cookie := range registration.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("customer registration did not issue a session cookie")
	}
	homepage := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	homepage.AddCookie(sessionCookie)
	homepageResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(homepageResponse, homepage)
	if homepageResponse.Code != http.StatusOK ||
		!strings.Contains(homepageResponse.Body.String(), `href="/account" aria-label="View your profile"`) ||
		!strings.Contains(homepageResponse.Body.String(), ">Log out</button>") ||
		strings.Contains(homepageResponse.Body.String(), `href="templates/login.html">Login</a>`) {
		t.Fatalf("signed-in buyer homepage did not show profile and logout: %d %s", homepageResponse.Code, homepageResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("customer dashboard request returned %d; want 403", recorder.Code)
	}
}

func TestSupplierDashboardAndLogout(t *testing.T) {
	app := newTestApplication(t)
	token, csrfCookie := getCSRFToken(t, app, "/templates/supplier-register.html")
	registration := postForm(t, app, "/register/supplier", url.Values{
		"name":           {"Test Supplier"},
		"business_name":  {"Test Farm"},
		"email":          {"supplier-login@example.test"},
		"category":       {"dairy"},
		"password":       {"StrongPass1!"},
		"terms_accepted": {"yes"},
	}, token, csrfCookie)
	if registration.Code != http.StatusSeeOther {
		t.Fatalf("supplier registration returned %d: %s", registration.Code, registration.Body.String())
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/login.html")
	login := postForm(t, app, "/login", url.Values{
		"email":    {"supplier-login@example.test"},
		"password": {"StrongPass1!"},
	}, token, csrfCookie)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/index.html" {
		t.Fatalf("supplier login returned %d, Location %q: %s", login.Code, login.Header().Get("Location"), login.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("supplier login did not issue a session cookie")
	}
	homepage := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	homepage.AddCookie(sessionCookie)
	homepageResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(homepageResponse, homepage)
	if homepageResponse.Code != http.StatusOK ||
		!strings.Contains(homepageResponse.Body.String(), `href="/account" aria-label="View your profile"`) ||
		!strings.Contains(homepageResponse.Body.String(), ">Log out</button>") {
		t.Fatalf("signed-in supplier homepage did not show profile and logout: %d %s", homepageResponse.Code, homepageResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Good morning, Test Farm") {
		t.Fatalf("supplier dashboard returned %d: %s", recorder.Code, recorder.Body.String())
	}
	csrfMatch := csrfInputPattern.FindStringSubmatch(recorder.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("supplier dashboard did not render a logout CSRF token")
	}
	var dashboardCSRFCookie *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			dashboardCSRFCookie = cookie
		}
	}
	if dashboardCSRFCookie == nil {
		t.Fatal("supplier dashboard did not set a logout CSRF cookie")
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(url.Values{
		"csrf_token": {csrfMatch[1]},
	}.Encode()))
	logoutRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutRequest.Header.Set("Origin", "http://example.test")
	logoutRequest.Host = "example.test"
	logoutRequest.AddCookie(sessionCookie)
	logoutRequest.AddCookie(dashboardCSRFCookie)
	logoutResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusSeeOther {
		t.Fatalf("supplier logout returned %d: %s", logoutResponse.Code, logoutResponse.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("dashboard remained accessible after logout: status %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/index.html", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `href="templates/login.html">Login</a>`) ||
		strings.Contains(recorder.Body.String(), ">Log out</button>") {
		t.Fatalf("homepage did not return to guest navigation after logout: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestPublicInformationPagesShowAuthenticatedNavigation(t *testing.T) {
	app := newTestApplication(t)
	tests := []struct {
		path string
	}{
		{path: "/templates/about.html"},
		{path: "/templates/suppliers.html"},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			guest := httptest.NewRecorder()
			app.mux.ServeHTTP(guest, httptest.NewRequest(http.MethodGet, test.path, nil))
			if guest.Code != http.StatusOK ||
				!strings.Contains(guest.Body.String(), `href="/templates/login.html">Login</a>`) ||
				strings.Contains(guest.Body.String(), `action="/logout"`) {
				t.Fatalf("guest GET %s returned incorrect navigation: %d %s", test.path, guest.Code, guest.Body.String())
			}

			_, sessionCookie := createAccountSession(
				t, app, "Supplier Contact", "Navigation Farm", strings.TrimPrefix(test.path, "/templates/")+"@example.test", "supplier")
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.AddCookie(sessionCookie)
			authenticated := httptest.NewRecorder()
			app.mux.ServeHTTP(authenticated, request)
			body := authenticated.Body.String()
			if authenticated.Code != http.StatusOK ||
				!strings.Contains(body, `<a href="/supplier/dashboard">Supplier dashboard</a>`) ||
				!strings.Contains(body, `href="/account">Profile</a>`) ||
				!strings.Contains(body, `action="/logout" method="POST" class="header-logout-form"`) ||
				!strings.Contains(body, `class="site-logout-button">Log out</button>`) ||
				strings.Contains(body, `href="/templates/login.html">Login</a>`) {
				t.Fatalf("supplier GET %s returned incorrect navigation: %d %s", test.path, authenticated.Code, body)
			}
		})
	}
}

func TestBuyerCanSeeRealActiveSuppliersOnSuppliersPage(t *testing.T) {
	app := newTestApplication(t)
	supplierID, _ := createAccountSession(t, app, "Supplier Contact", "Current Olive Farm", "current@example.test", "supplier")
	if _, err := app.db.Exec("UPDATE accounts SET category = 'olive-oil' WHERE id = ?", supplierID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec(`
INSERT INTO products (supplier_id, name, category, price, active)
VALUES (?, 'Current harvest oil', 'olive-oil', 12.5, 1)`, supplierID); err != nil {
		t.Fatal(err)
	}

	blockedSupplierID, _ := createAccountSession(t, app, "Blocked Contact", "Blocked Farm", "blocked@example.test", "supplier")
	if _, err := app.db.Exec("INSERT INTO blocked_accounts (account_id) VALUES (?)", blockedSupplierID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec(`
INSERT INTO accounts (name, business_name, email, role, status, password_hash)
VALUES ('Pending Contact', 'Pending Farm', 'pending@example.test', 'supplier', 'pending', 'test-hash')`); err != nil {
		t.Fatal(err)
	}

	_, buyerSession := createAccountSession(t, app, "Marketplace Buyer", "", "buyer@example.test", "customer")
	request := httptest.NewRequest(http.MethodGet, "/templates/suppliers.html", nil)
	request.AddCookie(buyerSession)
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK ||
		!strings.Contains(body, `data-category="olive-oil" data-search="Current Olive Farm Olive oil"`) ||
		!strings.Contains(body, "1 supplier") ||
		!strings.Contains(body, "1 active product") ||
		strings.Contains(body, "Blocked Farm") ||
		strings.Contains(body, "Pending Farm") ||
		strings.Contains(body, "current@example.test") {
		t.Fatalf("buyer did not see only actual active suppliers: %d %s", recorder.Code, body)
	}
	for _, sampleName := range []string{"Papadopoulos Farms", "Aegean Seafood Co.", "Nemea Winery", "Arcadian Dairy"} {
		if strings.Contains(body, sampleName) {
			t.Fatalf("suppliers page still contains sample supplier %q: %s", sampleName, body)
		}
	}
}

func TestRegistrationRejectsDuplicateEmailRegardlessOfCase(t *testing.T) {
	app := newTestApplication(t)
	token, csrfCookie := getCSRFToken(t, app, "/templates/supplier-register.html")
	registrationValues := url.Values{
		"name":           {"Test Supplier"},
		"business_name":  {"Test Farm"},
		"email":          {"duplicate@example.test"},
		"category":       {"dairy"},
		"password":       {"StrongPass1!"},
		"terms_accepted": {"yes"},
	}
	registration := postForm(t, app, "/register/supplier", registrationValues, token, csrfCookie)
	if registration.Code != http.StatusSeeOther {
		t.Fatalf("supplier registration returned %d: %s", registration.Code, registration.Body.String())
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/supplier-register.html")
	registrationValues.Set("email", "DUPLICATE@example.test")
	duplicate := postForm(t, app, "/register/supplier", registrationValues, token, csrfCookie)
	if duplicate.Code != http.StatusUnprocessableEntity || !strings.Contains(duplicate.Body.String(), "An account with this email already exists") {
		t.Fatalf("duplicate email registration returned %d: %s", duplicate.Code, duplicate.Body.String())
	}
	var accountCount int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM accounts WHERE lower(email) = ?", "duplicate@example.test").Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 1 {
		t.Fatalf("duplicate email registrations created %d accounts; want 1", accountCount)
	}
}

func TestRegistrationRequiresStrongPassword(t *testing.T) {
	app := newTestApplication(t)
	tests := []struct {
		name     string
		password string
	}{
		{name: "too short", password: "Aa1!"},
		{name: "missing uppercase", password: "strongpass1!"},
		{name: "missing symbol", password: "StrongPass1"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, csrfCookie := getCSRFToken(t, app, "/templates/auth.html")
			response := postForm(t, app, "/register", url.Values{
				"name":     {"Test Buyer"},
				"email":    {fmt.Sprintf("password-test-%d@example.test", index)},
				"password": {test.password},
				"role":     {"customer"},
			}, token, csrfCookie)
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "at least 8 characters") {
				t.Fatalf("registration with invalid password returned %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestInitializeDatabaseActivatesLegacyPendingSuppliers(t *testing.T) {
	app := newTestApplication(t)
	if _, err := app.db.Exec(`
INSERT INTO accounts (name, business_name, email, role, status, password_hash)
VALUES ('Legacy Supplier', 'Legacy Farm', 'legacy@example.test', 'supplier', 'pending', 'test-hash')`); err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(app.db); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := app.db.QueryRow("SELECT status FROM accounts WHERE email = ?", "legacy@example.test").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("legacy supplier status is %q; want active", status)
	}
}

func TestAdminCanSearchBlockUnblockAndDeleteAccounts(t *testing.T) {
	app := newTestApplication(t)
	adminPassword := "test-admin-password-123!"
	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	app.adminEmail = "admin@example.test"
	app.adminHash = adminHash

	hiddenPath := httptest.NewRecorder()
	app.mux.ServeHTTP(hiddenPath, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if hiddenPath.Code != http.StatusNotFound {
		t.Fatalf("public admin URL returned %d; want 404", hiddenPath.Code)
	}
	homepage := httptest.NewRecorder()
	app.mux.ServeHTTP(homepage, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if strings.Contains(homepage.Body.String(), app.adminPath) {
		t.Fatal("homepage disclosed the private administrator path")
	}

	supplierID, supplierSession := createAccountSession(
		t, app, "Supplier Contact", "Olive Farm", "supplier-admin@example.test", "supplier")
	supplierPassword := "supplier-test-password-2026!"
	supplierHash, err := bcrypt.GenerateFromPassword([]byte(supplierPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec("UPDATE accounts SET password_hash = ? WHERE id = ?", supplierHash, supplierID); err != nil {
		t.Fatal(err)
	}
	buyerID, _ := createAccountSession(
		t, app, "Buyer Contact", "", "buyer-admin@example.test", "customer")
	if _, err := app.db.Exec(`
INSERT INTO products (supplier_id, name, category, price, active)
VALUES (?, 'Admin test olive oil', 'olive-oil', 12.5, 1)`, supplierID); err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	app.mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, app.adminPath+"/accounts", nil))
	if unauthorized.Code != http.StatusSeeOther ||
		unauthorized.Header().Get("Location") != app.adminPath+"/login" {
		t.Fatalf("unauthenticated admin request returned %d and Location %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}
	if strings.Contains(unauthorized.Body.String(), "Olive Farm") {
		t.Fatal("unauthenticated admin request exposed account data")
	}

	token, csrfCookie := getCSRFToken(t, app, app.adminPath+"/login")
	badLogin := postForm(t, app, app.adminPath+"/login", url.Values{
		"email":    {"admin@example.test"},
		"password": {"wrong-admin-password"},
	}, token, csrfCookie)
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect admin password returned %d", badLogin.Code)
	}

	token, csrfCookie = getCSRFToken(t, app, app.adminPath+"/login")
	adminLogin := postForm(t, app, app.adminPath+"/login", url.Values{
		"email":    {"ADMIN@example.test"},
		"password": {adminPassword},
	}, token, csrfCookie)
	if adminLogin.Code != http.StatusSeeOther ||
		adminLogin.Header().Get("Location") != app.adminPath+"/accounts" {
		t.Fatalf("admin login returned %d and Location %q: %s", adminLogin.Code, adminLogin.Header().Get("Location"), adminLogin.Body.String())
	}
	var adminCookie *http.Cookie
	for _, responseCookie := range adminLogin.Result().Cookies() {
		if responseCookie.Name == adminCookieName {
			adminCookie = responseCookie
		}
	}
	if adminCookie == nil {
		t.Fatal("admin login did not issue an administrator session cookie")
	}

	searchPath := app.adminPath + "/accounts?q=Olive"
	token, csrfCookie = getCSRFToken(t, app, searchPath, adminCookie)
	searchPage := httptest.NewRecorder()
	searchRequest := httptest.NewRequest(http.MethodGet, searchPath, nil)
	searchRequest.AddCookie(adminCookie)
	app.mux.ServeHTTP(searchPage, searchRequest)
	if searchPage.Code != http.StatusOK ||
		!strings.Contains(searchPage.Body.String(), "Olive Farm") ||
		strings.Contains(searchPage.Body.String(), "buyer-admin@example.test") {
		t.Fatalf("admin account search returned %d: %s", searchPage.Code, searchPage.Body.String())
	}

	blockResponse := postForm(t, app, app.adminPath+"/accounts/"+strconv.FormatInt(supplierID, 10)+"/block", url.Values{
		"q": {"Olive"},
	}, token, csrfCookie, adminCookie)
	if blockResponse.Code != http.StatusSeeOther ||
		!strings.Contains(blockResponse.Header().Get("Location"), "q=Olive") {
		t.Fatalf("blocking supplier returned %d and Location %q", blockResponse.Code, blockResponse.Header().Get("Location"))
	}
	blockedDashboard := httptest.NewRecorder()
	blockedRequest := httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	blockedRequest.AddCookie(supplierSession)
	app.mux.ServeHTTP(blockedDashboard, blockedRequest)
	if blockedDashboard.Code != http.StatusSeeOther {
		t.Fatalf("blocked supplier dashboard returned %d; want redirect to login", blockedDashboard.Code)
	}
	token, csrfCookie = getCSRFToken(t, app, "/templates/login.html")
	blockedLogin := postForm(t, app, "/login", url.Values{
		"email":    {"supplier-admin@example.test"},
		"password": {supplierPassword},
	}, token, csrfCookie)
	if blockedLogin.Code != http.StatusUnauthorized || !strings.Contains(blockedLogin.Body.String(), "currently blocked") {
		t.Fatalf("blocked supplier login returned %d: %s", blockedLogin.Code, blockedLogin.Body.String())
	}
	blockedProducts := httptest.NewRecorder()
	app.mux.ServeHTTP(blockedProducts, httptest.NewRequest(http.MethodGet, "/templates/products.html", nil))
	if blockedProducts.Code != http.StatusOK || strings.Contains(blockedProducts.Body.String(), "Admin test olive oil") {
		t.Fatalf("blocked supplier product remained public: %d %s", blockedProducts.Code, blockedProducts.Body.String())
	}

	token, csrfCookie = getCSRFToken(t, app, app.adminPath+"/accounts", adminCookie)
	unblockResponse := postForm(t, app, app.adminPath+"/accounts/"+strconv.FormatInt(supplierID, 10)+"/unblock", url.Values{}, token, csrfCookie, adminCookie)
	if unblockResponse.Code != http.StatusSeeOther {
		t.Fatalf("unblocking supplier returned %d: %s", unblockResponse.Code, unblockResponse.Body.String())
	}
	restoredDashboard := httptest.NewRecorder()
	restoredRequest := httptest.NewRequest(http.MethodGet, "/supplier/dashboard", nil)
	restoredRequest.AddCookie(supplierSession)
	app.mux.ServeHTTP(restoredDashboard, restoredRequest)
	if restoredDashboard.Code != http.StatusOK {
		t.Fatalf("unblocked supplier dashboard returned %d", restoredDashboard.Code)
	}

	token, csrfCookie = getCSRFToken(t, app, app.adminPath+"/accounts", adminCookie)
	deleteResponse := postForm(t, app, app.adminPath+"/accounts/"+strconv.FormatInt(supplierID, 10)+"/delete", url.Values{}, token, csrfCookie, adminCookie)
	if deleteResponse.Code != http.StatusSeeOther {
		t.Fatalf("deleting supplier returned %d: %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	var remainingProducts int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM products WHERE supplier_id = ?", supplierID).Scan(&remainingProducts); err != nil {
		t.Fatal(err)
	}
	if remainingProducts != 0 {
		t.Fatalf("deleting supplier left %d products; want none", remainingProducts)
	}
	var remainingAccounts int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM accounts WHERE id IN (?, ?)", supplierID, buyerID).Scan(&remainingAccounts); err != nil {
		t.Fatal(err)
	}
	if remainingAccounts != 1 {
		t.Fatalf("delete action left %d of 2 test accounts; want only the buyer", remainingAccounts)
	}
}

func TestConfigureAdminRequiresPrivatePathAndCredentials(t *testing.T) {
	t.Setenv("ADMIN_PATH", "")
	t.Setenv("ADMIN_EMAIL", "")
	t.Setenv("ADMIN_PASSWORD", "")
	path, email, passwordHash, err := configureAdmin()
	if err != nil || path != "" || email != "" || len(passwordHash) != 0 {
		t.Fatalf("empty admin configuration returned path=%q email=%q error=%v", path, email, err)
	}

	t.Setenv("ADMIN_EMAIL", "admin@example.test")
	t.Setenv("ADMIN_PASSWORD", "a-strong-administrator-password")
	if _, _, _, err := configureAdmin(); err == nil {
		t.Fatal("administrator credentials without a private path were accepted")
	}

	t.Setenv("ADMIN_PATH", "/admin")
	if _, _, _, err := configureAdmin(); err == nil {
		t.Fatal("short public admin path was accepted")
	}

	t.Setenv("ADMIN_PATH", "/private-admin-path-for-test-123456")
	path, email, passwordHash, err = configureAdmin()
	if err != nil {
		t.Fatalf("valid administrator settings returned error: %v", err)
	}
	if path != "/private-admin-path-for-test-123456" || email != "admin@example.test" ||
		bcrypt.CompareHashAndPassword(passwordHash, []byte("a-strong-administrator-password")) != nil {
		t.Fatalf("valid administrator settings were not loaded correctly: path=%q email=%q", path, email)
	}
}

func TestListenAddressUsesRenderPort(t *testing.T) {
	t.Setenv("ADDR", "")
	t.Setenv("PORT", "")
	address, err := listenAddress()
	if err != nil || address != ":8080" {
		t.Fatalf("default listen address = %q, %v; want :8080", address, err)
	}

	t.Setenv("PORT", "10000")
	address, err = listenAddress()
	if err != nil || address != ":10000" {
		t.Fatalf("Render listen address = %q, %v; want :10000", address, err)
	}

	t.Setenv("ADDR", "127.0.0.1:9000")
	address, err = listenAddress()
	if err != nil || address != "127.0.0.1:9000" {
		t.Fatalf("explicit listen address = %q, %v; want 127.0.0.1:9000", address, err)
	}

	t.Setenv("ADDR", "")
	t.Setenv("PORT", "invalid")
	if _, err := listenAddress(); err == nil {
		t.Fatal("invalid Render port was accepted")
	}
}

func TestPublicInformationAndAccountHelpPages(t *testing.T) {
	app := newTestApplication(t)
	guestHomepage := httptest.NewRecorder()
	app.mux.ServeHTTP(guestHomepage, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if guestHomepage.Code != http.StatusOK ||
		!strings.Contains(guestHomepage.Body.String(), `href="templates/login.html">Login</a>`) ||
		strings.Contains(guestHomepage.Body.String(), ">Log out</button>") {
		t.Fatalf("guest homepage displayed incorrect account navigation: %d %s", guestHomepage.Code, guestHomepage.Body.String())
	}
	tests := []struct {
		path string
		text string
	}{
		{path: "/templates/info.html", text: "How to use About Food"},
		{path: "/forgot", text: "Self-service password resets are not available yet"},
		{path: "/style.css", text: "body"},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		app.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), test.text) {
			t.Errorf("GET %s returned %d or missing expected content %q", test.path, recorder.Code, test.text)
		}
	}
}

func TestBuyerCanViewOwnProfileButCannotManageSupplierProducts(t *testing.T) {
	app := newTestApplication(t)
	_, sessionCookie := createAccountSession(t, app, "Buyer Name", "", "buyer@example.test", "customer")
	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), "buyer@example.test") ||
		!strings.Contains(recorder.Body.String(), "Buyer account") ||
		!strings.Contains(recorder.Body.String(), `action="/logout"`) {
		t.Fatalf("buyer profile did not show account details and logout: %d %s", recorder.Code, recorder.Body.String())
	}

	token, csrfCookie := getCSRFToken(t, app, "/templates/login.html")
	request = httptest.NewRequest(http.MethodGet, "/supplier/products", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("buyer product-management request returned %d; want 403", recorder.Code)
	}
	response := postForm(t, app, "/supplier/products", url.Values{
		"name":     {"Should be rejected"},
		"category": {"other"},
		"price":    {"2.50"},
	}, token, csrfCookie, sessionCookie)
	if response.Code != http.StatusForbidden {
		t.Fatalf("buyer product creation returned %d; want 403", response.Code)
	}
}

func TestSupplierCanManageOnlyOwnProducts(t *testing.T) {
	app := newTestApplication(t)
	supplierID, supplierSession := createAccountSession(t, app, "Supplier One", "Farm One", "one@example.test", "supplier")
	otherSupplierID, otherSession := createAccountSession(t, app, "Supplier Two", "Farm Two", "two@example.test", "supplier")

	profileRequest := httptest.NewRequest(http.MethodGet, "/account", nil)
	profileRequest.AddCookie(supplierSession)
	profileResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(profileResponse, profileRequest)
	if profileResponse.Code != http.StatusOK ||
		!strings.Contains(profileResponse.Body.String(), "one@example.test") ||
		!strings.Contains(profileResponse.Body.String(), "Farm One") ||
		!strings.Contains(profileResponse.Body.String(), `href="/supplier/products"`) {
		t.Fatalf("supplier profile did not show supplier details and product link: %d %s", profileResponse.Code, profileResponse.Body.String())
	}

	token, csrfCookie := getCSRFToken(t, app, "/templates/supplier-products.html", supplierSession)
	createRequest := httptest.NewRequest(http.MethodPost, "/supplier/products", strings.NewReader(url.Values{
		"csrf_token":  {token},
		"name":        {"Olive oil"},
		"description": {"Cold pressed"},
		"category":    {"olive-oil"},
		"price":       {"12.50"},
		"unit":        {"per litre"},
		"active":      {"yes"},
	}.Encode()))
	createRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRequest.Header.Set("Origin", "http://example.test")
	createRequest.Host = "example.test"
	createRequest.AddCookie(csrfCookie)
	createRequest.AddCookie(supplierSession)
	createResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusSeeOther || createResponse.Header().Get("Location") != "/supplier/products?notice=created" {
		t.Fatalf("supplier product creation returned %d: %s", createResponse.Code, createResponse.Body.String())
	}

	var productID, ownerID int64
	if err := app.db.QueryRow("SELECT id, supplier_id FROM products WHERE name = ?", "Olive oil").Scan(&productID, &ownerID); err != nil {
		t.Fatal(err)
	}
	if ownerID != supplierID {
		t.Fatalf("product owner is %d; want %d", ownerID, supplierID)
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/supplier-products.html", otherSession)
	otherUpdateRequest := httptest.NewRequest(http.MethodPost, "/supplier/products/"+strconv.FormatInt(productID, 10)+"/update", strings.NewReader(url.Values{
		"csrf_token": {token},
		"name":       {"Stolen listing"},
		"category":   {"other"},
		"price":      {"1.00"},
	}.Encode()))
	otherUpdateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	otherUpdateRequest.Header.Set("Origin", "http://example.test")
	otherUpdateRequest.Host = "example.test"
	otherUpdateRequest.AddCookie(csrfCookie)
	otherUpdateRequest.AddCookie(otherSession)
	otherUpdate := httptest.NewRecorder()
	app.mux.ServeHTTP(otherUpdate, otherUpdateRequest)
	if otherUpdate.Code != http.StatusNotFound {
		t.Fatalf("different supplier updating product returned %d; want 404", otherUpdate.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/supplier/products", nil)
	request.AddCookie(supplierSession)
	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Olive oil") {
		t.Fatalf("supplier product page did not show owned listing: %d %s", recorder.Code, recorder.Body.String())
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/supplier-products.html", supplierSession)
	updateRequest := httptest.NewRequest(http.MethodPost, "/supplier/products/"+strconv.FormatInt(productID, 10)+"/update", strings.NewReader(url.Values{
		"csrf_token": {token},
		"name":       {"Olive oil updated"},
		"category":   {"olive-oil"},
		"price":      {"13.00"},
	}.Encode()))
	updateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updateRequest.Header.Set("Origin", "http://example.test")
	updateRequest.Host = "example.test"
	updateRequest.AddCookie(csrfCookie)
	updateRequest.AddCookie(supplierSession)
	updateResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusSeeOther || updateResponse.Header().Get("Location") != "/supplier/products?notice=updated" {
		t.Fatalf("supplier updating own product returned %d: %s", updateResponse.Code, updateResponse.Body.String())
	}
	_, err := app.db.Exec("DELETE FROM products WHERE id = ? AND supplier_id = ?", productID, otherSupplierID)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err := app.db.QueryRow("SELECT name FROM products WHERE id = ?", productID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Olive oil updated" {
		t.Fatalf("product was unexpectedly changed by another supplier: %q", name)
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/supplier-products.html", otherSession)
	otherDeleteRequest := httptest.NewRequest(http.MethodPost, "/supplier/products/"+strconv.FormatInt(productID, 10)+"/delete", strings.NewReader(url.Values{
		"csrf_token": {token},
	}.Encode()))
	otherDeleteRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	otherDeleteRequest.Header.Set("Origin", "http://example.test")
	otherDeleteRequest.Host = "example.test"
	otherDeleteRequest.AddCookie(csrfCookie)
	otherDeleteRequest.AddCookie(otherSession)
	otherDeleteResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(otherDeleteResponse, otherDeleteRequest)
	if otherDeleteResponse.Code != http.StatusNotFound {
		t.Fatalf("different supplier deleting product returned %d; want 404", otherDeleteResponse.Code)
	}

	token, csrfCookie = getCSRFToken(t, app, "/templates/supplier-products.html", supplierSession)
	deleteRequest := httptest.NewRequest(http.MethodPost, "/supplier/products/"+strconv.FormatInt(productID, 10)+"/delete", strings.NewReader(url.Values{
		"csrf_token": {token},
	}.Encode()))
	deleteRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRequest.Header.Set("Origin", "http://example.test")
	deleteRequest.Host = "example.test"
	deleteRequest.AddCookie(csrfCookie)
	deleteRequest.AddCookie(supplierSession)
	deleteResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusSeeOther {
		t.Fatalf("supplier deleting own product returned %d: %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	var remaining int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM products WHERE id = ?", productID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("product still exists after owner deleted it")
	}
}

func TestActiveSupplierProductsAppearInMarketplace(t *testing.T) {
	app := newTestApplication(t)
	supplierID, _ := createAccountSession(t, app, "Supplier Name", "Visible Farm", "visible@example.test", "supplier")
	if _, err := app.db.Exec(`
INSERT INTO products (supplier_id, name, description, category, price, unit, active)
VALUES (?, 'Market olive oil', 'Local harvest', 'olive-oil', 8.75, 'per litre', 1)`, supplierID); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/templates/products.html", nil))
	if recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), "Market olive oil") ||
		!strings.Contains(recorder.Body.String(), "Visible Farm") ||
		!strings.Contains(recorder.Body.String(), "8.75") ||
		!strings.Contains(recorder.Body.String(), "Olive oil") ||
		!strings.Contains(recorder.Body.String(), `class="product-card-footer"`) {
		t.Fatalf("public marketplace did not display active supplier product: %d %s", recorder.Code, recorder.Body.String())
	}

	if _, err := app.db.Exec("UPDATE products SET active = 0 WHERE supplier_id = ?", supplierID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	app.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/templates/products.html", nil))
	if recorder.Code != http.StatusOK ||
		strings.Contains(recorder.Body.String(), "Market olive oil") ||
		!strings.Contains(recorder.Body.String(), "No supplier products are available yet") {
		t.Fatalf("hidden product appeared in marketplace: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestRegisterRejectsInvalidCSRFAndCrossOrigin(t *testing.T) {
	app := newTestApplication(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/register/supplier", strings.NewReader(url.Values{
		"name":           {"Attacker"},
		"business_name":  {"Attacker Farm"},
		"email":          {"attacker@example.test"},
		"category":       {"olive-oil"},
		"password":       {"StrongPass1!"},
		"terms_accepted": {"yes"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("registration without CSRF token returned %d; want 403", recorder.Code)
	}
	var accountCount int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 0 {
		t.Fatalf("invalid CSRF request created %d accounts", accountCount)
	}

	token, csrfCookie := getCSRFToken(t, app, "/templates/supplier-register.html")
	values := url.Values{
		"name":           {"Attacker"},
		"business_name":  {"Attacker Farm"},
		"email":          {"attacker@example.test"},
		"category":       {"olive-oil"},
		"password":       {"StrongPass1!"},
		"terms_accepted": {"yes"},
	}
	values.Set("csrf_token", token)
	crossOriginRequest := httptest.NewRequest(http.MethodPost, "/register/supplier", strings.NewReader(values.Encode()))
	crossOriginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOriginRequest.Header.Set("Origin", "http://attacker.test")
	crossOriginRequest.Host = "example.test"
	crossOriginRequest.AddCookie(csrfCookie)
	crossOriginResponse := httptest.NewRecorder()
	app.mux.ServeHTTP(crossOriginResponse, crossOriginRequest)
	if crossOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin registration returned %d; want 403", crossOriginResponse.Code)
	}
	if err := app.db.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 0 {
		t.Fatalf("cross-origin request created %d accounts", accountCount)
	}
}
