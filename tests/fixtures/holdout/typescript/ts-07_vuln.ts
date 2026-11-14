// holdout corpus entry ts-07 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
app.use((req, res, next) => { verifyPermissions(req); next(); });
