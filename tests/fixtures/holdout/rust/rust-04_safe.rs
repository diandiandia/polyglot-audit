// holdout corpus entry rust-04 role=safe (development-time synthetic; derived from knowledge card)
// NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
let len = u16::try_from(user_size).map_err(|_| Error::Overflow)?;
