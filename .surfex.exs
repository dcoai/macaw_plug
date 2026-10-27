[
  sources: ["spec/*.md"],
  heading_ids: ~r/\{#(?<id>[a-z0-9-]+)\}\s*$/,
  tests: ["test/**/*_test.exs"],
  require: [code: [:implements, :excuses], test_hint: [:verifies]],
  adoption: :trust,
  # Type specs document the functions' contracts; the functions carry the relation
  # (a test can exercise a function, never a type).
  classes: [{"type", "types document the functions' contracts, which carry the relation"}],
  rules: [%{class: "type", kinds: [:type]}],
  # The overview describes the library; it asserts nothing a test checks.
  spec_classes: [
    {"orientation", "describes what macaw_plug holds and how it is used; asserts nothing a test checks",
     files: ["spec/00-overview.md", "spec/README.md"]},
    # A chapter's opening paragraph says why its module exists and where it came from;
    # every behavior it names is stated, and verified, in the chapter's own sections.
    {"chapter-intro",
     "a chapter's introduction: the module's purpose and provenance; each behavior it names is stated and verified in the chapter's sections"}
  ]
]
