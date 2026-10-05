# Third-party rule data

The EasyList authors (https://easylist.to/) are the source of the imported
domain data. Official license: https://easylist.to/pages/licence.html
The derived lists/nullad-hosts.txt and extension/domain-rules.js data are
licensed under Creative Commons Attribution-ShareAlike 3.0 Unported:
https://creativecommons.org/licenses/by-sa/3.0/
Legal code: https://creativecommons.org/licenses/by-sa/3.0/legalcode

Upstream commit: 129e63db3096f78e6dc94ac7ca6a15e27b5d1b79
Upstream date: 2026-10-05T10:22:01Z

Changes: Only unconditional ||ASCII-domain^ rules extracted, deduplicated and sorted; literal-host exceptions (even path/type-specific), their ancestor blocks and child domains excluded; two local business endpoints excluded; redundant child rules removed; independent original local domains included. Generic/regex ABP exceptions cannot be expressed by this domain-only subset; it is not full ABP list execution.

Full original inputs are committed in rules/vendor/*.source with hashes and
paths in rules/sources.lock.json. Regenerate offline with
python scripts/update-bundled-rules.py; --refresh explicitly fetches a new
pinned version from the official repository. No runtime downloads occur.
This data notice does not relicense the independent MIT application code.

These lists include advertising and tracking; false positives remain possible.
Disable bundled rules or allow a site/domain when required. No warranty or
upstream endorsement is implied.
