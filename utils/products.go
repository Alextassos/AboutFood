package utils

import (
	"database/sql"
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
)

func (app *application) publicProductsPage(w http.ResponseWriter, r *http.Request) {
	rows, err := app.db.Query(`
SELECT products.id, products.name, products.description, products.category,
       products.price, products.unit, accounts.business_name
FROM products
JOIN accounts ON accounts.id = products.supplier_id
WHERE products.active = 1 AND accounts.role = 'supplier' AND accounts.status = 'active'
  AND NOT EXISTS (
      SELECT 1 FROM blocked_accounts WHERE blocked_accounts.account_id = accounts.id
  )
ORDER BY products.created_at DESC, products.id DESC`)
	if err != nil {
		log.Printf("load marketplace products: %v", err)
		http.Error(w, "Unable to load marketplace products.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	products := make([]product, 0)
	for rows.Next() {
		var item product
		if err := rows.Scan(
			&item.ID, &item.Name, &item.Description, &item.Category,
			&item.Price, &item.Unit, &item.SupplierName,
		); err != nil {
			log.Printf("read marketplace product: %v", err)
			http.Error(w, "Unable to load marketplace products.", http.StatusInternalServerError)
			return
		}
		item.CategoryLabel = categoryLabel(item.Category)
		products = append(products, item)
	}
	if err := rows.Err(); err != nil {
		log.Printf("iterate marketplace products: %v", err)
		http.Error(w, "Unable to load marketplace products.", http.StatusInternalServerError)
		return
	}
	data := pageData{Products: products}
	user, accountErr := app.currentAccount(r)
	if accountErr == nil {
		data.Authenticated = true
		data.Role = user.Role
		data.CSRFToken, err = app.issueCSRF(w)
		if err != nil {
			log.Printf("create marketplace logout CSRF token: %v", err)
			http.Error(w, "Unable to load marketplace products.", http.StatusInternalServerError)
			return
		}
	} else if errors.Is(accountErr, sql.ErrNoRows) {
		app.clearCookie(w, sessionCookieName)
	} else if !errors.Is(accountErr, http.ErrNoCookie) {
		log.Printf("load marketplace account navigation: %v", accountErr)
		http.Error(w, "Unable to load marketplace products.", http.StatusInternalServerError)
		return
	}
	app.renderTemplate(w, "products.html", data)
}

func (app *application) marketplaceSuppliers() ([]supplier, error) {
	rows, err := app.db.Query(`
SELECT accounts.business_name, accounts.category, COUNT(products.id)
FROM accounts
LEFT JOIN products ON products.supplier_id = accounts.id AND products.active = 1
WHERE accounts.role = 'supplier' AND accounts.status = 'active'
  AND NOT EXISTS (
      SELECT 1 FROM blocked_accounts WHERE blocked_accounts.account_id = accounts.id
  )
GROUP BY accounts.id, accounts.business_name, accounts.category
ORDER BY lower(accounts.business_name), accounts.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	suppliers := make([]supplier, 0)
	for rows.Next() {
		var item supplier
		if err := rows.Scan(&item.BusinessName, &item.Category, &item.ProductCount); err != nil {
			return nil, err
		}
		if !validCategory(item.Category) {
			item.Category = "other"
		}
		item.CategoryLabel = categoryLabel(item.Category)
		suppliers = append(suppliers, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return suppliers, nil
}

func (app *application) supplierProductsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/supplier/products" && r.URL.Path != "/templates/supplier-products.html" {
		http.NotFound(w, r)
		return
	}
	user, ok := app.requireSupplierAccount(w, r)
	if !ok {
		return
	}

	products, err := app.productsForSupplier(user.ID)
	if err != nil {
		log.Printf("load supplier products for account %d: %v", user.ID, err)
		http.Error(w, "Unable to load your products.", http.StatusInternalServerError)
		return
	}
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("create product management CSRF token: %v", err)
		http.Error(w, "Unable to load your products.", http.StatusInternalServerError)
		return
	}

	notice := ""
	switch r.URL.Query().Get("notice") {
	case "created":
		notice = "Product added."
	case "updated":
		notice = "Product updated."
	case "deleted":
		notice = "Product deleted."
	}
	app.renderTemplate(w, "supplier-products.html", pageData{
		CSRFToken: token,
		Name:      user.BusinessName,
		Products:  products,
		Notice:    notice,
	})
}

func (app *application) productsForSupplier(supplierID int64) ([]product, error) {
	rows, err := app.db.Query(`
SELECT id, name, description, category, price, unit, active
FROM products
WHERE supplier_id = ?
ORDER BY created_at DESC, id DESC`, supplierID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := make([]product, 0)
	for rows.Next() {
		var item product
		var active int
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Category, &item.Price, &item.Unit, &active); err != nil {
			return nil, err
		}
		item.Active = active == 1
		products = append(products, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return products, nil
}

func (app *application) createSupplierProduct(w http.ResponseWriter, r *http.Request) {
	user, ok := app.requireSupplierAccount(w, r)
	if !ok || !app.parsePost(w, r) {
		return
	}
	item, err := parseProductForm(r)
	if err != nil {
		app.renderProductError(w, user, err.Error())
		return
	}
	active := 0
	if item.Active {
		active = 1
	}
	_, err = app.db.Exec(`
INSERT INTO products (supplier_id, name, description, category, price, unit, active)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, item.Name, item.Description, item.Category, item.Price, item.Unit, active)
	if err != nil {
		log.Printf("create product for supplier %d: %v", user.ID, err)
		http.Error(w, "Unable to save this product.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/supplier/products?notice=created", http.StatusSeeOther)
}

func (app *application) updateSupplierProduct(w http.ResponseWriter, r *http.Request) {
	user, ok := app.requireSupplierAccount(w, r)
	if !ok || !app.parsePost(w, r) {
		return
	}
	id, ok := productID(w, r)
	if !ok {
		return
	}
	item, err := parseProductForm(r)
	if err != nil {
		app.renderProductError(w, user, err.Error())
		return
	}
	active := 0
	if item.Active {
		active = 1
	}
	result, err := app.db.Exec(`
UPDATE products
SET name = ?, description = ?, category = ?, price = ?, unit = ?, active = ?
WHERE id = ? AND supplier_id = ?`,
		item.Name, item.Description, item.Category, item.Price, item.Unit, active, id, user.ID)
	if err != nil {
		log.Printf("update product %d for supplier %d: %v", id, user.ID, err)
		http.Error(w, "Unable to update this product.", http.StatusInternalServerError)
		return
	}
	if !productExistsForSupplier(w, result, id) {
		return
	}
	http.Redirect(w, r, "/supplier/products?notice=updated", http.StatusSeeOther)
}

func (app *application) deleteSupplierProduct(w http.ResponseWriter, r *http.Request) {
	user, ok := app.requireSupplierAccount(w, r)
	if !ok || !app.parsePost(w, r) {
		return
	}
	id, ok := productID(w, r)
	if !ok {
		return
	}
	result, err := app.db.Exec("DELETE FROM products WHERE id = ? AND supplier_id = ?", id, user.ID)
	if err != nil {
		log.Printf("delete product %d for supplier %d: %v", id, user.ID, err)
		http.Error(w, "Unable to delete this product.", http.StatusInternalServerError)
		return
	}
	if !productExistsForSupplier(w, result, id) {
		return
	}
	http.Redirect(w, r, "/supplier/products?notice=deleted", http.StatusSeeOther)
}

func productID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "Product not found.", http.StatusNotFound)
		return 0, false
	}
	return id, true
}

func productExistsForSupplier(w http.ResponseWriter, result sql.Result, id int64) bool {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("check affected rows for product %d: %v", id, err)
		http.Error(w, "Unable to confirm the product update.", http.StatusInternalServerError)
		return false
	}
	if rowsAffected != 1 {
		http.Error(w, "Product not found.", http.StatusNotFound)
		return false
	}
	return true
}

func parseProductForm(r *http.Request) (product, error) {
	item := product{
		Name:        strings.TrimSpace(r.PostForm.Get("name")),
		Description: strings.TrimSpace(r.PostForm.Get("description")),
		Category:    strings.TrimSpace(r.PostForm.Get("category")),
		Unit:        strings.TrimSpace(r.PostForm.Get("unit")),
		Active:      r.PostForm.Get("active") == "yes",
	}
	price, err := strconv.ParseFloat(strings.TrimSpace(r.PostForm.Get("price")), 64)
	switch {
	case len(item.Name) < 2 || len(item.Name) > 120:
		return product{}, errors.New("Product name must be between 2 and 120 characters.")
	case len(item.Description) > 1000:
		return product{}, errors.New("Product description must be no more than 1000 characters.")
	case !validCategory(item.Category):
		return product{}, errors.New("Select a valid product category.")
	case err != nil || math.IsNaN(price) || math.IsInf(price, 0) || price <= 0 || price > 1_000_000 ||
		math.Abs(price*100-math.Round(price*100)) > 1e-8:
		return product{}, errors.New("Enter a price greater than zero and no more than 1,000,000.")
	case len(item.Unit) > 30:
		return product{}, errors.New("Unit must be no more than 30 characters.")
	}
	item.Price = price
	return item, nil
}

func (app *application) renderProductError(w http.ResponseWriter, user account, message string) {
	products, err := app.productsForSupplier(user.ID)
	if err != nil {
		log.Printf("reload supplier products for account %d: %v", user.ID, err)
		http.Error(w, "Unable to load your products.", http.StatusInternalServerError)
		return
	}
	token, err := app.issueCSRF(w)
	if err != nil {
		log.Printf("refresh product form CSRF token: %v", err)
		http.Error(w, "Unable to reload your products. Please try again.", http.StatusInternalServerError)
		return
	}
	app.renderTemplateStatus(w, "supplier-products.html", pageData{
		CSRFToken: token,
		Name:      user.BusinessName,
		Products:  products,
		Error:     message,
	}, http.StatusUnprocessableEntity)
}
