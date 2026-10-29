GHOST BRAND KIT v1.0 (locked 28 October 2026; logo re-locked 29 October 2026)

WHAT'S INSIDE
  svg/        Master files. Use these whenever you can; they scale to any size.
    ghost-logo-primary.svg          the full logo: outlined cells on a lavender body, for white/light backgrounds
    ghost-logo-on-violet.svg        the same cells on a white body, for violet backgrounds
    ghost-logo-on-ink.svg           the primary colors; the lavender body carries it on near-black (merch, code boxes)
    ghost-logo-one-color-ink.svg    all ink, the cell faces cut out, for one-color print, engraving and coins
    ghost-logo-one-color-white.svg  all white, one-color on dark or photo backgrounds
    ghost-logo-small.svg            the small cut for 16 to 32 px: the body alone in violet, eyes cut out, on a 16 px grid
    ghost-lockup-*.svg              logo + "ghost" wordmark, four color versions (text is outlined, no font needed)
  png/        The logos (not the small cut) at 256 and 1024 px, and lockups at 2400 px wide. Transparent backgrounds.
  app-icon/   Square app icons (violet and white) at 1024, 512, 192. Phones and stores round the corners themselves.
  favicon/    favicon.svg, favicon.ico (16/32/48) and favicon-16/32/48.png, all from the small cut;
              apple-touch-icon.png (180), the white app icon.
  social/     ghost-og-image-1200x630.png (link preview), ghost-avatar-800.png (profile picture),
              ghost-x-profile.png (400, X profile: white circle, the logo 75% of its width), and their SVGs.
  fonts/      Instrument Sans and IBM Plex Mono with their open font licences (free to use and embed).

  The PNGs and favicon.ico are made from the SVGs by scripts/build-brand-kit.sh (rsvg-convert and convert).

THE LOGO
  A pixel ghost on a 124-unit grid. Nineteen cells, each 20 x 20 with corners of 2, on a pitch of 26
  (at 0 / 26 / 52 / 78 / 104), each outlined in ink inside its edge (a 4-unit line on a 16 x 16 square
  set in by 2), and filled violet tint #EEEAFF, ghost violet #6B4CFF or white in a fixed order.
  Rows from the top: the three middle cells; the two sides and the center, with the two cells between
  left empty as the eyes; all five; all five; the two sides and the center as the three-point hem.
  Behind the cells a lavender body (#C9BCFF) fills the gaps and runs 3 units past the outer cells,
  with the eyes left as holes. Meaning: a ghost made of blocks. Your coins are one among many.

RULES
  Clear space    at least one cell pitch (21% of the logo's width) of empty space on every side
  Minimum size   16 px on screen, 6 mm in print; under 24 px use the small cut (ghost-logo-small.svg),
                 since the outlines blur at that size
  Lockup         logo height = the height of the wordmark's "h"; gap = a third of the logo;
                 wordmark is always lowercase "ghost", Instrument Sans SemiBold, tracking -4.5%
  Never          recolor or reorder the cells, fill in the eyes, drop the body, rotate it, stretch it,
                 or use the full logo under 24 px

COLORS
  Paper         #FFFFFF   pages
  Mist          #F5F5F8   panels, page behind cards
  Line          #E4E3EC   borders, dividers
  Ink           #0E0D1A   text, the logo's cell outlines
  Body text     #4A4860
  Quiet text    #6E6C82   (on #ECEBF2 use #5F5D73 instead)
  Ghost violet  #6B4CFF   logo cells and the small cut, main buttons, links
  Violet tint   #EEEAFF   highlights (put ink text on it, not violet)
  Summon mint   #4FF0C8   only when coins come back; use as a fill with ink text, never as text on white
  Light-first: white pages, ink text, violet used sparingly. Dark backgrounds only for code boxes and merch.

TYPE
  Instrument Sans   everything people read (headlines SemiBold, tight tracking)
  IBM Plex Mono     keys, amounts, addresses, anything people copy or verify
