#!/bin/bash
curl -kv https://monitor.certipath.com/fpki/download/all/p7b/ --output fpki_from_certipath.p7b
curl -kv https://monitor.certipath.com/fpki/download/all/csv/ --output fpki_from_certipath.csv
grep -oP "\bhttp://[^,]*\.crl" fpki_from_certipath.csv > discovered_crl_urls.txt
curl -kv https://raw.githubusercontent.com/GSA/fpki-guides/staging/_data/notifications.yml --output fpki_guides_notifications.yml
grep -oP "\bhttp://[^,]*\.crl" fpki_guides_notifications.yml >> discovered_crl_urls.txt
curl -kv https://api.fpki.io/v1/caPathAsPEM --output fpki_io.pem
grep -oP "\bhttp://[^,]*\.crl" fpki_io.pem >> discovered_crl_urls.txt
sort discovered_crl_urls.txt | uniq > unique_discovered_crls.txt
