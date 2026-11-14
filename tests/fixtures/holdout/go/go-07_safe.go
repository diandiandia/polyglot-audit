// holdout corpus entry go-07 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
clean := filepath.Clean(userInput); if strings.HasPrefix(clean, "..") { return }; target := filepath.Join(baseDir, clean)
