// holdout corpus entry csharp-02 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
SqlCommand cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'");
