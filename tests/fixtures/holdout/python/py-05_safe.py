# holdout corpus entry py-05 role=safe (development-time synthetic; derived from knowledge card)
# NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
