// holdout corpus entry kotlin-02 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
val target = intent.getParcelableExtra<Intent>("forward"); if (isValid(target)) startActivity(target)
