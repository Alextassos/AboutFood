const supplierSearch = document.querySelector("#supplier-search");
const supplierCards = Array.from(document.querySelectorAll(".supplier-card"));
const supplierFilters = Array.from(document.querySelectorAll(".supplier-filter"));
const supplierCount = document.querySelector(".supplier-result-count");
const supplierEmpty = document.querySelector(".supplier-search-empty");

let activeCategory = "all";

function updateSuppliers() {
    const query = supplierSearch.value.trim().toLocaleLowerCase();
    let visibleCount = 0;

    supplierCards.forEach((card) => {
        const matchesCategory = activeCategory === "all" || card.dataset.category === activeCategory;
        const matchesQuery = card.dataset.search.toLocaleLowerCase().includes(query);
        const isVisible = matchesCategory && matchesQuery;

        card.hidden = !isVisible;
        if (isVisible) visibleCount += 1;
    });

    supplierCount.textContent = `${visibleCount} ${visibleCount === 1 ? "supplier" : "suppliers"}`;
    supplierEmpty.hidden = visibleCount !== 0 || supplierCards.length === 0;
}

supplierSearch.addEventListener("input", updateSuppliers);

supplierFilters.forEach((filter) => {
    filter.addEventListener("click", () => {
        activeCategory = filter.dataset.category;

        supplierFilters.forEach((button) => {
            const isActive = button === filter;
            button.classList.toggle("is-active", isActive);
            button.setAttribute("aria-pressed", String(isActive));
        });

        updateSuppliers();
    });
});
