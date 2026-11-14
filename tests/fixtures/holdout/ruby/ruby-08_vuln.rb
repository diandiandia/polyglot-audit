# holdout corpus entry ruby-08 role=vuln (development-time synthetic; derived from knowledge card)
# NOT an independent holdout item; real holdout must be maintainer-authored. See tests/holdout/README.md
Pathname.new('/safe/dir').join(params[:path])
