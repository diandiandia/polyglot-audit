// holdout corpus entry go-06 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
query := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", name)
