// holdout corpus entry scala-04 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
implicit def toAdmin(u: User): Admin = Admin(u.name)
