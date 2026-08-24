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

# Buffered, printed only once every country fetched. Streamed as it arrived,
# a failure on the second country left the first one's networks already on
# stdout: a redirect then held a valid-looking partial list, every line a
# CIDR the portal accepts, silently missing half the region. That is the
# exact fragment the portal's whole-or-nothing fetch refuses, and the
# offline route has to refuse it the same way.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

for cc in "$@"; do
    cc=$(printf '%s' "$cc" | tr '[:upper:]' '[:lower:]')
    curl -fsS "https://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.zone" >> "$tmp" || {
        echo "could not fetch the list for '${cc}' - check the ISO country code; nothing printed" >&2
        exit 1
    }
done

cat "$tmp"
