// holdout corpus entry ts-05 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
enum Role { User = 1, Admin = 2 }; function setRole(r: Role) { ... }
