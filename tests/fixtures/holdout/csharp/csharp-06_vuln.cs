// holdout corpus entry csharp-06 role=vuln (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
public IActionResult Update([FromForm] User entity) { _db.Users.Update(entity); }
