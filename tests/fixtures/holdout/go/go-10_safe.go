// holdout corpus entry go-10 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
dec := json.NewDecoder(data); dec.DisallowUnknownFields(); dec.Decode(&adminObj)
