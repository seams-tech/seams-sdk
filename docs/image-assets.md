# Navbar Image Asset Plan

## Goal

Create consistent 3D menu assets for the wallet SDK Products dropdown:

- `Guides`
- `Tools`
- `Use cases`

Each tile needs four static variants:

- light mode wireframe
- light mode filled
- dark mode wireframe
- dark mode filled

The UI should transition from wireframe to filled on hover or focus. The assets must
share the same object, camera, crop, and anchor point within each tile so the transition
feels like a material pass revealing the existing form.

All assets must use perspective projection. The perspective lines should visibly align
to consistent vanishing points so the set follows an architectural blueprint system.

## Asset Matrix

Use the current navbar asset sizes unless the layout changes:

- `Guides`: `900 x 675`, large vertical tile
- `Tools`: `900 x 390`, horizontal tile
- `Use cases`: `900 x 390`, horizontal tile

Proposed filenames:

- `menu-guides-wire-light.png`
- `menu-guides-fill-light.png`
- `menu-guides-wire-dark.png`
- `menu-guides-fill-dark.png`
- `menu-tools-wire-light.png`
- `menu-tools-fill-light.png`
- `menu-tools-wire-dark.png`
- `menu-tools-fill-dark.png`
- `menu-use-cases-wire-light.png`
- `menu-use-cases-fill-light.png`
- `menu-use-cases-wire-dark.png`
- `menu-use-cases-fill-dark.png`

Use true transparent PNG output. Do not bake off-white, dark, or themed background
colors into the asset. Let the tile background, theme tokens, and CSS hover state supply
the surface color.

## Shared Visual System

All three objects should read as related SDK artifacts from one technical drawing set.

- Camera: perspective projection, three-quarter view, object angled from lower-left
  foreground to upper-right background.
- Perspective system: use two-point perspective as the default. Use one-point
  perspective only when the object is a direct corridor-like composition. Reserve
  three-point perspective for a dramatic tall `Guides` composition if it improves the
  scaffold/building read.
- Projection guides: add faint dotted projection lines from key object corners toward
  the active vanishing points. Keep them clipped inside the artwork bounds so they read
  as intentional blueprint construction marks.
- Line language: thin 3D CAD wireframe lines with visible construction geometry,
  bevel loops, panel seams, and measurement guides.
- Line hierarchy: outer silhouette and primary load-bearing edges are slightly thicker
  and darker. Interior mesh, secondary seams, and hidden/construction lines are lighter,
  thinner, and often dotted.
- Shape language: rounded rectangles, modular rails, translucent panels, secure
  hardware details, and small encoded labels.
- Palette, light mode:
  - wire lines: cool gray-lavender
  - construction lines: very pale lavender-gray
  - active accents: muted mint and soft purple
  - filled surfaces: translucent off-white, pearl, pale lavender glass
- Palette, dark mode:
  - wire lines: desaturated lavender-gray with higher contrast
  - construction lines: dim violet-gray
  - active accents: mint and muted violet
  - filled surfaces: smoky glass, dark graphite, soft purple reflections
- Rendering: clean studio render, no photographic texture, no grain, no heavy shadows.
- Background: true alpha transparency, with no baked background color, horizon line, or
  scenic environment.
- Composition: leave upper-left text-safe space because tile copy sits there.
- Detail density: enough mesh lines to feel technical at small navbar size, with clear
  silhouette at 50 percent scale.

Avoid: cartoon icons, flat vector style, logos, human hands, currency symbols, brand
marks, photoreal leather or metal, dense text blocks, and high-saturation gradients.

## Tile Concepts

### Guides

Object: unfolding blueprint path that becomes a scaffolded SDK building.

The image should combine a technical manual and an architectural wireframe. Pages or
panels unfold into a small stepped structure, with vertical measurement rails, waypoint
markers, and a thin route line that climbs through the structure. This keeps the current
building reference while making the object specific to implementation guidance.

Wireframe state:

- pale CAD lines
- clear two-point or subtle three-point perspective
- dotted projection lines extending from platform and scaffold corners
- visible page outlines and structural rails
- route line as a faint dotted path
- minimal filled surfaces

Filled state:

- translucent page planes and platform slabs appear
- route line becomes a soft mint/purple trace
- final platform marker glows subtly
- structural rails remain visible over the filled planes
- darker outline edges remain above translucent material fills

Hover animation:

- crossfade wireframe asset to filled asset over `220ms`
- draw or reveal the route trace from bottom-left to upper-right
- lift the final platform marker by `2px` with a subtle opacity increase

Prompt focus:

`A 3D CAD wireframe of an unfolding developer guide transforming into a scaffolded SDK building, perspective-projection three-quarter view with visible vanishing-point alignment, dotted projection lines from platform corners, pages as floor plates, route line, waypoint markers, darker outer outline edges, lighter dotted interior construction lines, rounded technical details, transparent background.`

### Tools

Object: compact SDK workbench module.

The image should look like a small secure hardware bench for passkeys, signing sessions,
and wallet UI primitives. Use a rectangular device body with rounded corners, socketed
modules, connector pins, a passkey chip, a signing-session cartridge, and short circuit
traces between them.

Wireframe state:

- device outline and bevel loops
- clear two-point perspective with corner projection lines
- empty module sockets
- trace grid and pin rows
- small labels such as `key`, `sig`, `ui`, and short hex fragments

Filled state:

- module blocks become translucent glass components
- selected traces pulse in mint
- passkey chip and session cartridge get subtle purple fills
- connector pins gain a pale highlight
- darker perimeter and module outlines remain visible over translucent fills

Hover animation:

- crossfade wireframe asset to filled asset over `180ms`
- pulse traces from left module to right module
- depress one tiny toggle by `1px`

Prompt focus:

`A compact SDK workbench device in 3D CAD wireframe, perspective-projection three-quarter view with two-point vanishing alignment, dotted projection lines from device corners, rounded rectangular module with passkey chip, signing-session cartridge, connector pins, circuit traces, darker perimeter outlines, lighter dotted interior construction lines, tiny technical labels, transparent background.`

### Use Cases

Object: policy-controlled transaction flow network.

The image should show a central wallet panel connected to several application flows:
payment, recovery, policy approval, and app integration. A small validator gate sits in
the middle so the object communicates policy-controlled signing.

Wireframe state:

- central wallet/card panel
- clear two-point perspective with aligned projection lines
- branching spline paths
- validator gate as a small bridge or lock-like module
- endpoint capsules for each flow
- short hash labels and binary fragments

Filled state:

- wallet panel and validator gate become translucent
- one path lights through the gate, then branches activate
- endpoint capsules receive soft mint/purple fills
- hash labels stay faint and secondary
- darker wallet, gate, and endpoint outlines remain visible over translucent fills

Hover animation:

- crossfade wireframe asset to filled asset over `220ms`
- send one small packet through the validator gate
- activate endpoints in sequence with a `40ms` stagger

Prompt focus:

`A policy-controlled wallet transaction network in 3D CAD wireframe, perspective-projection three-quarter view with two-point vanishing alignment, dotted projection lines from wallet and gate corners, central wallet panel connected to branching payment, recovery, approval, and app integration nodes, validator gate in the middle, darker outer outlines, lighter dotted interior construction lines, thin hash labels, transparent background.`

## Prompt Construction Process

1. Lock the base prompt.
   - Write one shared style paragraph used verbatim for all assets.
   - Add only the tile object paragraph and state delta per render.
   - Keep camera, vanishing points, crop, object scale, and lighting identical across
     states.

2. Generate the light wireframe variant first.
   - Choose the strongest composition for each tile.
   - Reject outputs where the silhouette is unclear, text-safe space is crowded, or the
     object reads as a generic icon.

3. Use image-to-image or seed reuse for the other three variants.
   - The filled state must preserve the wireframe geometry.
   - The dark variant must preserve the same object placement.
   - Only material, line contrast, and accent brightness should change.

4. Compare all twelve assets together.
   - Verify shared perspective projection, vanishing-point alignment, and line hierarchy.
   - Verify each object is distinct at navbar size.
   - Verify the filled variants feel more active without becoming visually heavier than
     the tile text.

5. Export and inspect in the actual navbar.
   - Check light and dark mode.
   - Check default, hover, focus-visible, and reduced-motion states.
   - Check desktop at the Products dropdown size and mobile if these images are reused.

## Base Prompt Template

Use this shared paragraph for every generation:

```text
Clean 3D CAD technical illustration for a wallet SDK navbar tile, perspective-projection
three-quarter camera with consistent vanishing-point alignment, object angled from
lower-left foreground to upper-right background, dotted projection lines extending from
important object corners toward the vanishing points, darker and slightly thicker outer
outline edges, lighter dotted interior construction lines, visible bevel loops and panel
seams, subtle rounded technical hardware geometry, no people, no brand logos, no
currency symbols, transparent background, text-safe space in the upper-left, high
readability at small UI size, refined enterprise product aesthetic, muted lavender-gray
linework with mint and soft purple technical accents.
```

Then append:

- tile object prompt
- state prompt: `wireframe state` or `filled translucent material state`
- theme prompt: `light mode palette` or `dark mode palette`
- output prompt: exact pixel size and transparent PNG

## State Prompts

Wireframe state:

```text
Wireframe state: perspective-projected CAD lines with aligned vanishing points, faint
dotted projection lines from key corners, darker and slightly thicker outer silhouette
edges, lighter dotted interior mesh and construction guides, very sparse translucent
planes, minimal accent color, no strong fills, no heavy shadows.
```

Filled state:

```text
Filled translucent material state: preserve the exact perspective geometry, vanishing
points, projection guides, and camera, add translucent glass-like panels and module
fills, keep darker outline edges and lighter dotted interior lines visible on top,
activate a few mint and soft purple traces, restrained glow, no heavy shadows.
```

Light mode palette:

```text
Light mode palette: pale warm-white transparent surfaces, cool gray-lavender linework,
very light construction lines, muted mint and soft purple accents, airy low-contrast
render suitable for an off-white menu tile.
```

Dark mode palette:

```text
Dark mode palette: smoky translucent graphite surfaces, lavender-gray linework with
clear contrast, dim violet construction lines, mint and muted purple accents, controlled
glow suitable for a dark menu tile.
```

## Consistency Checklist

- Same camera angle across all three tile families.
- Same perspective-projection method and vanishing-point discipline across all three
  tile families.
- Same crop and object anchor within each wireframe/filled pair.
- Same line hierarchy across light and dark mode: darker/thicker outlines, lighter
  dotted interiors, faint dotted projection guides.
- Same accent colors and glow intensity across tiles.
- Distinct silhouette for each tile: scaffold, workbench module, branching network.
- Text-safe area remains open in the upper-left.
- Assets remain readable when rendered around `300px` wide.
- Filled state aligns closely enough with wireframe state for a clean hover crossfade.
- Projection guide lines remain visible enough to create an architectural blueprint feel
  without competing with the primary object silhouette.
- Dark mode uses contrast through line brightness and translucent fills, with controlled
  glow.
- Light mode stays pale enough to support current Seams navbar copy.

## Frontend Animation Contract

Use two stacked images per tile:

- base image: wireframe variant
- hover image: filled variant

Recommended CSS behavior:

- default: wireframe opacity `1`, filled opacity `0`
- hover/focus-visible: wireframe opacity `.25`, filled opacity `1`
- transition: `opacity 180ms ease-out` for Tools, `opacity 220ms ease-out` for Guides
  and Use cases
- reduced motion: no animated transform, opacity switch may remain instant or use the
  existing global reduced-motion behavior

Optional overlay animations can be implemented in CSS or SVG after the static images are
approved. Keep those overlays tiny: route trace for Guides, trace pulse for Tools, packet
movement for Use cases.

## Acceptance Criteria

- The three default wireframe images feel calm and architectural in the closed menu.
- Hover reveals a materially richer version of the same object.
- Light and dark variants feel like theme-specific renders of the same system.
- The set avoids generic wallet imagery and communicates developer guidance, SDK tools,
  and policy-controlled application flows.
- The generated files can replace the current `menu-guides.png`, `menu-tools.png`, and
  `menu-use-cases.png` references through typed asset imports with no runtime branching
  beyond theme and hover state selection.
