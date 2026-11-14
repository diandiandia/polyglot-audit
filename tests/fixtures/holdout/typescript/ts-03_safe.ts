// holdout corpus entry ts-03 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
function isAdmin(x: any): x is Admin { return x && x.role === 'admin'; }
