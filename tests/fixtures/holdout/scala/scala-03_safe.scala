// holdout corpus entry scala-03 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
sql"SELECT * FROM t WHERE id = $id".query[Row]
