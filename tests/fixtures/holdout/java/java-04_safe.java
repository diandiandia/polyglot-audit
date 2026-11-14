// holdout corpus entry java-04 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE id = ?"); ps.setString(1, id);
