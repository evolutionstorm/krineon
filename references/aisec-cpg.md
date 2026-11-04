# Fraunhofer AISEC CPG integration

Krineon can consume the JSON graph produced by Fraunhofer AISEC
`cpg-neo4j`. Install the tool separately with only the language frontends needed
for the target. Krineon does not download or build it.

When `cpg-neo4j` is on `PATH`, `static_analysis_pipeline.py` automatically:

1. Selects a compatible frontend from the pinned source tree.
2. Executes the exporter without a Neo4j service.
3. Retains the raw JSON graph, stdout, stderr, executable hash, source-manifest
   hash, command, and frontend maturity.
4. Normalizes graph counts and DFG, EOG, CFG, CDG, AST, and call-edge families.
5. Keeps the result outside the findings and validation queues until a bounded
   runtime experiment confirms a security-relevant disagreement.

Use `--aisec-cpg-language` only for a mixed-language tree where automatic
selection chose the wrong component. Supported values are `java`, `cxx`, `go`,
`python`, `rust`, `llvm`, and `typescript`.

Java, C/C++, Go, Python, and Rust frontends are treated as maintained source
analysis. LLVM is incubating. TypeScript/JavaScript is experimental and remains
hypothesis-only regardless of apparent graph completeness.

AISEC CPG can infer data-flow edges for unresolved calls. Krineon records this
possibility and never describes an inferred edge as a proved flow. Before a path
can advance, the campaign must establish attacker control, resolve every guard,
run positive and enforcing-negative controls on the shipped artifact, and pass
independent coordinator replay.

Official resources:

- <https://github.com/Fraunhofer-AISEC/cpg>
- <https://www.codyze.io/>
