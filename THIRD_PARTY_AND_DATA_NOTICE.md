# Third-party and data notice

This repository does not grant a licence to redistribute League of Legends
replay files, client memory images, Match Details responses, player identifiers,
or other Riot/Tencent data. Those inputs are intentionally excluded from the
AI handoff package. Obtain them only through an authorised channel and review
the applicable terms before sharing them.

Original code and documentation in the public source repository are licensed
under GPL-3.0-only; see `LICENSE`. That licence does not cover third-party
Replay data, client/runtime binaries, Match Details, player identifiers,
trademarks, or upstream code that is not part of this repository. The
`evidence/exact_build_route_attestations/` files remain local because they
contain raw Replay payload bytes. Published bounded summaries are historical
attestations, not permission to redistribute their underlying inputs.

The old reverse-engineering workspace contained a snapshot of an upstream
project named `Mowokuma/ROFL`. That snapshot was removed from the cleaned
workspace because no licence file was present. The retained historical note
in `docs/WARD_SPAWN_UPSTREAM_REVERSE_ENGINEERING.md` identifies the upstream
commit for provenance; it is not a licence or a redistributed source copy.

League of Legends and Riot Games are trademarks of their respective owners.
This project is an independent research tool and is not endorsed by Riot Games
or Tencent.
