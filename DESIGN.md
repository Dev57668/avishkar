---
name: Second Read
description: A security-debt scorer for AI-written code, presented as an annotated lab notebook with real dark "screens" set into the paper.
colors:
  cobalt: "#2457ff"
  cyan-signal: "#22d3ee"
  teal-highlight: "#086e8b"
  signal-violet: "#6b3fd4"
  ink-amber: "#b26a00"
  ink-red: "#cf2f3f"
  ink-green: "#2a7d34"
  paper-bg: "#f4f1e8"
  paper-panel: "#fffdf6"
  paper-panel-muted: "#f8f5ec"
  ink: "#151b28"
  ink-muted: "#4a5466"
  ink-faint: "#656e80"
  pen: "#2343c9"
  screen-bg: "#0b1220"
  screen-panel: "#111a2c"
  screen-panel-muted: "#162032"
  screen-text: "#edf1f7"
  screen-text-muted: "#a4adbd"
  crit: "#ff4d5e"
  high: "#ff8a4d"
  warn: "#ffb547"
  ok: "#34d399"
  low: "#7cb4ff"
  info: "#9aa7b8"
typography:
  display:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(40px, 6vw, 72px)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(30px, 3.8vw, 44px)"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-0.03em"
  step-title:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "25px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "Geist Mono, ui-monospace, monospace"
    fontSize: "12px"
    fontWeight: 400
    letterSpacing: "0.06em"
  hand:
    fontFamily: "Caveat, Segoe Print, cursive"
    fontSize: "28px"
    fontWeight: 600
rounded:
  pill: "999px"
  sm: "4px"
  md: "6px"
  lg: "8px"
  panel: "10px"
  xl: "16px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  section: "88px"
components:
  button-primary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "11px 18px"
  button-primary-solid:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper-panel}"
    rounded: "{rounded.pill}"
    padding: "11px 18px"
  button-primary-solid-hover:
    backgroundColor: "{colors.cobalt}"
  button-on-ink:
    backgroundColor: "{colors.paper-panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "11px 18px"
  console-button-primary:
    backgroundColor: "{colors.cobalt}"
    textColor: "#ffffff"
    rounded: "{rounded.pill}"
    padding: "8px 14px"
  tour-panel:
    backgroundColor: "{colors.paper-panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
  findings-strip:
    backgroundColor: "{colors.screen-bg}"
    textColor: "{colors.screen-text}"
    rounded: "{rounded.lg}"
    padding: "22px 26px"
  closing-band:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper-panel}"
    rounded: "{rounded.lg}"
    padding: "30px 32px"
  kpi-card:
    backgroundColor: "{colors.screen-panel}"
    textColor: "{colors.screen-text}"
    rounded: "{rounded.xl}"
    padding: "16px"
  pill-severity-critical:
    backgroundColor: "{colors.crit}"
    textColor: "#2a0006"
    rounded: "{rounded.pill}"
  pill-severity-medium:
    backgroundColor: "{colors.warn}"
    textColor: "#2b1d00"
    rounded: "{rounded.pill}"
---

# Design System: Second Read

## Overview

**Creative North Star: "The Annotated Lab Notebook"**

Second Read presents itself as a researcher's field notebook, not a product brochure. The landing page is warm paper (`#f4f1e8`) ruled with a faint blueprint grid, drifting watercolor washes, and hand-drawn margin doodles in a pen-blue (`#2343c9`) that annotate the text the way a reviewer scribbles on a printout — a stray `{ }`, an `eval() ?!`, a `TODO: fix L46`. Set into that paper, wherever the product needs to show something real — the recorded findings of a sample scan, an annotated code excerpt, a diff, the console itself — the page switches to an actual dark "screen": `#0b1220`–`#060a11` glass with a cyan/cobalt/amber/red data vocabulary. The paper never pretends to be a terminal, and the screens never pretend to be paper; the contrast between the two registers *is* the idea — a human, hand-annotated read of a machine process.

The paper register is now confident rather than whispered: bold display and section headings, one phrase per heading set in that section's own ink colour, and a six-colour ink set (teal, cobalt, violet, amber, red, green) that colour-codes the six steps of the tour. Colour is still never decoration: on paper it marks *which step or section you are in*; on screens it marks *severity and state*. The console (the real dashboard under `#app`) lives permanently in the dark-screen register and shares the screens' palette, so the page's screens and the real product are visually the same place.

Motion is sparing and authored: the findings strip's tiles land once, the tour's progress rail fills as you scroll and each step's dot pulses once on arrival, and the code figure's scan line sweeps when its step opens. There is no ambient 3D or looping hero animation.

**Key Characteristics:**
- Two coherent registers, strictly separated: warm hand-annotated paper for narrative, and a dark cyan/cobalt/amber/red "screen" vocabulary for anything that shows live or recorded machine output.
- Bold, colour-keyed headings: weight 700, one coloured phrase per heading, no eyebrow labels or number badges above them.
- A pinned, six-step tour replaces long scrolling for the explanatory middle of the page; each step owns one ink colour.
- Pill-shaped (`999px`) buttons and status indicators everywhere; rectangular, modestly rounded containers for everything else.
- Severity and completeness states are a first-class visual vocabulary (critical/high/medium/low/informational, plus an explicit "not evaluated"/"incomplete" state) because the product's honesty claim depends on never drawing an unscored or unevaluated item as if it were clean.

## Colors

Two palettes sharing one action color (cobalt): a paper palette of ink plus six step inks for the narrative, and a cyan-accented dark palette for every screen, demo window, and the console.

### Primary
- **Cobalt** (`#2457ff`): the action color in both registers — link and hover color on paper, the hover fill of the solid paper button, the console's primary button. On paper it also inks the hero's "Read" and tour step 2; it is the only hue that appears as both an action and a step ink.

### Secondary
- **Cyan Signal** (`#22d3ee`, dark-screen variant `#22e1ff`): the accent reserved for dark screens only — console links and focus rings, the gauge's bright end, the code figure's scan beam. Never appears on the paper register.

### Tertiary — the step inks (paper only)
Six inks, one per tour step and section, each dark enough to read as text on paper:
- **Teal Highlight** (`#086e8b`): the logo stroke, the tour heading's coloured phrase, step 1, the first hero stat and tag.
- **Cobalt** (`#2457ff`): step 2 and the second hero stat (see Primary).
- **Signal Violet** (`#6b3fd4`): step 3, the console heading's coloured phrase, the second hero tag.
- **Ink Amber** (`#b26a00`): step 4, the limitations heading's coloured phrase, the FAQ `+` markers.
- **Ink Red** (`#cf2f3f`): step 5 and paper-side critical numbers.
- **Ink Green** (`#2a7d34`): step 6, the third hero stat, the "change" row of the results table.

### Neutral — Paper
- **Paper** (`#f4f1e8`): the page background, with the blueprint grid drawn over it at low opacity.
- **Panel** (`#fffdf6`): card/figure/table/tour-panel background, slightly warmer and lighter than the page so panels read as sheets laid on the desk.
- **Panel Muted** (`#f8f5ec`): the tour panel's title bar and the formula well.
- **Ink** (`#151b28`) / **Ink Muted** (`#4a5466`) / **Ink Faint** (`#656e80`): primary, secondary, and tertiary text on paper. Ink also fills the closing band and the solid button.
- **Pen** (`#2343c9`): the color of the hand-drawn doodle strokes and margin annotations only — never body text or UI chrome.

### Neutral — Screen
- **Screen** (`#0b1220`) / **Screen Deep** (`#060a11`): the two dark backgrounds — the console shell and the findings strip (`#0b1220`) versus the code and diff windows (`#060a11`). Treat them as the same register at two depths, not two different dark themes.
- **Screen Panel** (`#111a2c`) / **Screen Panel Muted** (`#162032`): card and well backgrounds inside the console.
- **Screen Text** (`#edf1f7`) / **Screen Text Muted** (`#a4adbd`): primary and secondary text on dark screens.

### Severity & Status
Every finding, decision, and completeness state draws from one fixed mapping, identical in the console, the findings strip and the code figure:
- **Critical** (`#ff4d5e`) · **High** (`#ff8a4d`) · **Medium / Warn** (`#ffb547`) · **Low** (`#7cb4ff`; `#b7c3d1` on the landing page's screens) · **Informational** (`#9aa7b8`)
- **Ok / pass** (`#34d399`) · **Bad / block** (`#ff5468`, aliased with Critical) · **Warn / would-block** (`#ffb547`)

### Named Rules
**The Screen Rule.** Cyan Signal, and the deep `#060a11`/`#0b1220` backgrounds, exist only inside something the user would recognize as a screen (console, findings strip, code figure, diff, dialog, toast). The paper register never borrows them; its accents are the six step inks.

**The One Ink Per Place Rule.** On paper, each step or section owns exactly one ink, and everything that marks "you are here" in it — the heading's coloured phrase, the step's dot and underline, the tour panel's top band and label — uses that ink. Never mix two step inks inside one element.

**The Honest State Rule.** An incomplete, not-evaluated, or not-yet-scored item is never drawn as zero, clean, or green. It gets its own label (`n/a`, `not calculated`, `not evaluated`) and, where a gauge or chart would otherwise show a value, a gap or an explicit muted state instead.

## Typography

**Display/Body Font:** Geist (variable, weights 100–900), with `ui-sans-serif, system-ui, sans-serif` fallback.
**Mono Font:** Geist Mono, for code, data, labels, and anything tabular or precise.
**Hand Font:** Caveat (weight 600 only), for the margin-doodle annotations.

**Character:** A clean, slightly technical grotesque (Geist) carries every real sentence and number, set heavy (700) wherever it heads something; its mono sibling marks anything that is data, code, or a precise label; Caveat is the one indulgence, reserved entirely for the hand-drawn marginalia.

### Hierarchy
- **Display** (700, `clamp(40px,6vw,72px)`, line-height 1, -0.035em): the single `<h1>` on the landing page only, with its final word in Cobalt.
- **Headline** (700, `clamp(30px,3.8vw,44px)`, line-height 1.12, -0.03em, balanced wrap): section titles. One phrase per headline is set in the section's ink.
- **Step title** (700, 25px, line-height 1.2): the tour's step list; faint until reached, ink when open, with a 3px underline in the step's ink. The tour panel's own heading uses the same weight at 22px in the open step's ink.
- **Title** (600, 17px): card and sub-section headings, in both registers.
- **Body** (400, 16px/1.6; lede copy at 17px): running prose, capped near 700px measure on paper.
- **Label** (400–500, 12px, Geist Mono, letter-spacing 0.06em, often uppercase): table headers, pills, legends, KPI labels, timestamps — the "instrument readout" register.

### Named Rules
**The No Eyebrow Rule.** Nothing sits above a heading: no kicker, no "STEP 1 · …" label, no section-number badge. Sequence that matters is carried by a numbered dot (the tour) or by order alone.

**The One Indulgent Font Rule.** Caveat appears nowhere but the fixed-position doodle layer. If a UI element needs emphasis or personality, reach for Geist weight or a step ink, never the hand font.

## Layout

Paper pages are a single centered column, `max-width: 1160px`, `padding: 0 24px` (`.wrap`), laid over a 24×24px blueprint grid drawn in `rgba(36,87,255,.075)`. Sections carry `padding-top: 88px` as the standing vertical rhythm. The page runs: hero (copy beside a stat column) → findings strip → the pinned tour → console → limitations and the closing band.

**The tour** is the page's main structural device. On wide screens (≥901px) a tall track (one viewport plus 70vh per extra step) scrolls past a sticky pin set 60px below the top; inside the pin, a `1fr / 1.15fr` grid holds the numbered step list beside a fixed-height panel (`min(540px, 100vh − 150px)`), and scroll progress through the track selects the step, so the panel changes in place instead of the page growing. Under 900px the track and pin switch off: the steps become a horizontally scrolling row of pill tabs above the panel, and a tap swaps the scene. Without JavaScript every scene simply stacks in order.

The console uses a card grid instead of a narrative column: a 4-up KPI row (`.kpis`, 2-up under 760px) and a 2-up general grid (`.grid2`, 1-up under 760px). Density is deliberately higher than the paper register, consistent with an "operate" surface versus a "read" one.

Both registers share the same breakpoints: 760px (mobile), 860px (nav collapse), and 900px (column collapse and tour tabs).

## Elevation & Depth

Flat by default. Paper-register separation comes from a 1px or 1.5px border in `--line`/`--line-2` plus a panel-vs-page background shift. Dark screens separate panels the same way, with borders in `rgba(140,200,255,.12–.24)` against the two background depths. Shadows are reserved for things that float above the page: the tour panel, pinned over the scrolling paper (`0 24px 64px -28px rgba(21,27,40,.35)`); toasts (`0 6px 20px rgba(0,0,0,.5)`); and the modal backdrop dim. The tour's arriving-step pulse is a transient ring (`box-shadow` expanding 0→14px in the step's ink, once), not elevation.

### Named Rules
**The Flat Paper Rule.** Nothing laid *on* the paper casts a shadow — figures, tables, the findings strip, the closing band. Only an element that stays put while the paper moves under it (the pinned tour panel) or floats above the page (toasts, dialogs) may.

## Shapes

Two corner languages, split cleanly by function. **Pills** (`border-radius: 999px`) are reserved for anything clickable-as-a-chip or stateful: buttons, severity pills, status badges, filter chips, the mobile tour tabs. **Rectangles with modest rounding** carry everything else: 8px for paper panels, figures, tables, the findings strip and the closing band; 10px for the tour panel; 6px for smaller dark-screen wells (code header, diff); 4px for the strip's finding tiles; 16px for console cards and KPI tiles. Circles appear only as the tour's numbered dots and the pipeline's step numerals. Dashed borders (`1px dashed var(--line-2)`) survive only on the results table and the stat column's divider; solid borders are the default everywhere else. A coloured accent is never a thick border on a rounded box: the tour panel's 4px colour band is drawn inside its title bar, clipped by the panel's corners.

## Components

### Buttons
- **Shape:** pill (`border-radius: 999px`) in both registers; never any other radius.
- **Paper outline (default):** transparent background, 1px `--line-2` border, `--ink` text; hover darkens the border to full ink.
- **Paper solid:** ink-filled, cream text; hover shifts the fill to Cobalt.
- **On ink (closing band):** cream fill, ink text; hover turns Cobalt with cream text; cream focus ring.
- **Console primary:** Cobalt fill, white text, bold weight.
- **Console ghost/default:** translucent white fill (`rgba(255,255,255,.04)`) with a hairline border; hover brightens the border to Cyan Signal.
- **Disabled:** 50% opacity, no pointer, on every variant.

### Pills / Severity Badges
- **Shape:** full pill, small type (12–13px), bold weight for severity.
- **Severity:** solid fill per the Severity & Status palette, with a near-black or near-white text color chosen for contrast per swatch.
- **Status (pass/warn/block/health):** outline-only pill in the matching color (`st-ok`, `st-warn`, `st-bad`), so severity (solid) and decision/health (outline) stay visually distinct at a glance.
- **Hero tags:** 4px-rounded mono chips, each outlined and lettered in one step ink.

### Cards / Containers
- **Paper figure/panel:** 8px radius, 1px border, Panel background; a `figcaption` in mono sits below, caption-side bottom.
- **Console card (`.cs`, `.card`, `.kpi`):** 16px radius, Screen Panel background, hairline white-alpha border, 16px internal padding; KPI cards stack label / big tabular-numeral value / muted sub-line.
- **Closing band:** a solid ink sheet (8px radius, 30px 32px padding) carrying one bold 20–26px line in cream and the on-ink button; the last beat of the page.

### Inputs / Fields
- **Style (console only — paper has no form inputs):** dark fill (`rgba(0,0,0,.35)`), hairline border, 8px radius.
- **Focus:** border and outline shift to Cyan Signal (`:focus-visible` outline, 2px, offset 2–3px); on paper the focus ring is Cobalt.

### Navigation
- **Paper nav:** sticky top bar, transparent until scrolled, then a translucent paper-tinted blur; the current-section indicator is a 2px ink underline that slides and resizes under the active link (`.nav-ind`). Three links point into the tour and light by the open step.
- **Console nav (`.cnav`):** pill-shaped links; the current page gets a subtle filled pill (`rgba(255,255,255,.08)`) rather than an underline.
- **Mobile:** both collapse behind a burger; paper's menu drops open inline below the bar.

### Tour (signature component)
A numbered step list beside one fixed panel. Each step has a 30px circular dot carrying its numeral: faint outline when ahead, filled with the step's ink (cream numeral) once passed, and an outlined ring in the step's ink (scaled 1.15, one outward pulse) when open. A 3px rail runs through the dots; its fill is a gradient of the six inks laid over the full rail length, so each stretch keeps its own colour, and it grows continuously with scroll, reaching each dot exactly as that step opens. The open step's title turns ink with an ink underline that sweeps across, and its one-line description slides in beneath. The panel (Panel background, 10px radius, title bar with a 4px band and a counter in the open step's ink) cross-fades between scenes; scenes are `inert` while hidden. Arrow keys move between steps.

### Findings Strip (signature component)
A single dark screen band under the hero, built entirely from recorded scanner output: the security-debt index as a large red mono numeral with `/ 100`, then one 24px tile per finding, coloured by severity and grouped in rows by file (mono filename at left), then a legend of severity names and counts. Tiles carry their rule and location as a tooltip. On first view the tiles land once in order (scale and fade, 40ms apart); with reduced motion they are simply present. If the recorded data is missing the strip is not shown at all — never an invented number.

### Gauge (console)
A half-circle SVG dial: a muted full-arc track, a value arc filled with a Cyan→Amber→Red gradient (used purely as a 0–100 position cue, explicitly *not* a risk-band encoding), a large tabular-numeral center readout, and `0`/`100` end labels. When the value is unknown it renders no arc and the center reads "n/a — not calculated," per the Honest State Rule.

### Stepper (console)
A horizontal (mobile: vertical) row of named stages (Queued → Preparing → Scanning → Scoring → Saving → Done), each a bordered pill-dot plus label; done stages fill the dot green with a check glyph, the active stage pulses its border in Cyan Signal, and a failed run turns the final stage's dot red with an × rather than silently completing it.

### Annotated Code Scan (tour step 5)
A dark `#060a11` code block whose lines start dimmed to 32% opacity; when its step opens, a thin cyan beam sweeps down over ~1.8s, lighting each line it passes, and the flagged line takes a translucent crit-red wash with an inline annotation card (rule id, severity, finding prose, fix snippet) expanding beneath it. Without motion the final, annotated state is shown.

### Margin Doodle Layer
A fixed, pointer-events-none layer of hand-drawn SVG line doodles and Caveat text fragments, each gently bobbing on its own slow loop, all in Pen blue at ~16% opacity. Decorative only — never used to carry real content, and hidden entirely under 760px and under `prefers-reduced-motion: reduce`.

## Do's and Don'ts

### Do:
- **Do** keep Cyan Signal and the two dark backgrounds confined to literal screens (console, findings strip, code figure, diff, dialog, toast) — The Screen Rule.
- **Do** set headings at weight 700 and colour exactly one phrase per heading in that section's ink — The One Ink Per Place Rule.
- **Do** carry sequence with a numbered dot or plain order, never a label above the heading — The No Eyebrow Rule.
- **Do** render every pill-shaped element at `999px` radius; reserve 4–16px rounding for rectangular containers only.
- **Do** show an incomplete, not-evaluated, or uncalculated state with its own explicit label or gap — never as zero, clean, or green — The Honest State Rule.
- **Do** keep severity pills solid-filled and decision/status pills outline-only.
- **Do** source every number on the landing page from the recorded scan data, and hide the element rather than show a placeholder number when that data is missing.

### Don't:
- **Don't** add a box-shadow to anything laid on the paper (figures, tables, strip, closing band); only the pinned tour panel and floating toasts/dialogs carry one.
- **Don't** put a thick coloured border on a rounded container; draw the colour as a band inside it.
- **Don't** introduce a severity or status color outside the fixed Critical/High/Medium/Low/Informational and Ok/Warn/Bad mapping, or a seventh step ink.
- **Don't** add looping or ambient hero animation; motion is one authored moment per element (tiles land, rail fills, beam sweeps).
- **Don't** let the blueprint grid, watercolor wash, or doodle layer appear inside the console or any dark screen.
- **Don't** use the active-nav underline treatment in the console, or the console's filled-pill treatment on the paper nav.
