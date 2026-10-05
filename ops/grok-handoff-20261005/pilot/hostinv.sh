cd /
for f in $(find /usr/local/lib/aukora-boundary /etc/aukora-boundary-gate /etc/systemd/system -maxdepth 2 -type f \( -path '*aukora*' \) 2>/dev/null | sort); do echo "$(sha256sum $f | cut -c1-12) $f"; done
echo "PKG $(cd /opt/aukora-boundary-gate && find . -type f | sort | xargs sha256sum | sha256sum | cut -c1-12)"
