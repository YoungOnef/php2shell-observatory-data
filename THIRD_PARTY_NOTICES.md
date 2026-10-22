# Data attribution

The project catalogue is adapted from [Awesome Selfhosted data](https://github.com/awesome-selfhosted/awesome-selfhosted-data), copyright its contributors, licensed under [Creative Commons Attribution-ShareAlike 3.0 Unported](https://creativecommons.org/licenses/by-sa/3.0/). Changes: selecting metadata fields, cleaning Markdown descriptions, deriving GitHub ranks, identifying PHP scope, adding source checks and combining scoped evidence. The adapted catalogue fields remain under that license. A license copy is in `dist/licenses/awesome-selfhosted.txt`.

Imported assessment notes and status records originate from [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell), licensed under the European Union Public Licence 1.2. Changes: exact-name matching with the catalogue, mapping both-CVE statuses, and adding collection provenance. Source commit references and vendor links are preserved. A license copy is in `dist/licenses/ncsc.txt`.

Source metadata in `dist/data/projects.json` records the exact catalogue and inventory commits used in every generated snapshot. PHP advisory thresholds are sourced from php.net and the two PHP project security advisories linked in `config/advisory.json`.

The original dashboard and collection code are available under the accompanying MIT license. These terms do not replace the separate data licenses. The compiled data JSON contains separately attributed data components; retain attribution, provenance and applicable licenses when sharing it.

The interface loads DM Sans, Manrope and IBM Plex Mono from Google Fonts, falling back to installed fonts if unavailable. SVG UI symbols are included as inline paths without external icon dependencies.
