// holdout corpus entry go-03 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
val, ok := req.Body.(string); if !ok { return nil, errors.New("invalid") }
