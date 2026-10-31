# Third-party notices

Second Read's own code is not yet released under a license (see the repository root). The files below are third-party
and keep their own terms. They are bundled in `web/vendor/` so the site works offline.

| Component | Version | License | Where |
|---|---|---|---|
| Three.js | r160 | MIT (header in the file: Copyright 2010-2023 Three.js Authors) | `web/vendor/three.module.min.js` |
| GSAP | 3.12.5 | GreenSock "Standard No Charge" license, https://gsap.com/standard-license | `web/vendor/gsap.min.js` |
| Geist, Geist Mono | 2024 | SIL Open Font License 1.1 | `web/vendor/fonts/geist*.woff2` |
| Instrument Serif (italic) | 2022 | SIL Open Font License 1.1 | `web/vendor/fonts/instrument-serif-italic.woff2` |
| Caveat | 2014 | SIL Open Font License 1.1 | `web/vendor/fonts/caveat.woff2` |

Full OFL text and the exact copyright lines: `web/vendor/fonts/OFL.txt`.

## Things to know
* **GSAP is not OSI open source.** Its Standard license is free for most uses, including this project, but it has
  restrictions (for example, it may not be used to build tools that let end users create animations, in competition
  with GreenSock's products). Read the terms before using it in anything commercial. It is used only for small
  entrance/number animations in `web/landing.js`; replacing it with CSS animations would remove this dependency.
* The vendored files are unmodified upstream builds. Their versions were read from the file headers; there is no
  lockfile or checksum. If you update them, record the new version here.
* Removed as unused: ScrollTrigger and Lenis (they were bundled but never loaded).
* Fonts were verified from their embedded metadata, not from the upstream download pages.
