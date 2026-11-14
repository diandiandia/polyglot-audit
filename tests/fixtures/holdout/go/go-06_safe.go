// holdout corpus entry go-06 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
row := db.QueryRow("SELECT * FROM items WHERE name = ?", name)
