#!/bin/sh
# Prints the IPv4 networks allocated to the named countries, one CIDR per
# line, ready to paste into a protection region in the portal.
#
#   ./geo-zones.sh au nz      # oceania, near enough, for a game server
#
# Data comes from ipdeny.com's aggregated per-country zone files, which are
# built from the RIR delegation statistics. The portal's Fetch button pulls
# the same files, so this script is the offline route: for preparing a list
# away from the portal, or for a frontend whose egress is locked down. Both
# ways the result goes through the settings form and is validated on save,
# and nothing refreshes on a schedule. Allocations move slowly at this
# granularity - refresh a couple of times a year.
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <country-code>...    e.g. $0 au nz" >&2
    exit 1
fi

for cc in "$@"; do
    cc=$(printf '%s' "$cc" | tr '[:upper:]' '[:lower:]')
    curl -fsS "https://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.zone" || {
        echo "could not fetch the list for '${cc}' - check the ISO country code" >&2
        exit 1
    }
done
