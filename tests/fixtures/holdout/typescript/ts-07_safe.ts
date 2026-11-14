// holdout corpus entry ts-07 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
app.use(async (req, res, next) => { await verifyPermissions(req); next(); });
