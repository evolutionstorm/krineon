from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.framework_analysis_pipeline import build_relations, scan_javascript
from scripts.semantic_ir import build_semantic_ir


class SemanticIRTests(unittest.TestCase):
    def analysis(self, source: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "middleware.js"
            path.write_text(source, encoding="utf-8")
            facts, _ = scan_javascript(
                path,
                root,
                "source",
                {"requireAuth"},
                set(),
                1024 * 1024,
            )
            return {
                "framework": "nextjs",
                "runId": "fixture",
                "facts": facts,
                "relations": build_relations(root, facts),
            }

    def test_ir_records_scoped_flow_alias_mutation_and_unknowns(self) -> None:
        analysis = self.analysis(
            "function route(request) { requireAuth(request); "
            "const normalized = customDecode(request); request.path = normalized; "
            "execute(normalized); }\n"
        )
        ir = build_semantic_ir(analysis)
        self.assertTrue(ir["operations"])
        self.assertTrue(any(edge["kind"] == "mutation" for edge in ir["dataEdges"]))
        self.assertEqual(len(ir["securityPaths"]), 1)
        path = ir["securityPaths"][0]
        self.assertEqual(path["status"], "experiment-required")
        self.assertTrue(path["aliasMutationRisk"]["canInvalidate"])
        self.assertEqual(path["resourceAgreement"]["status"], "unknown")
        self.assertTrue(ir["experimentCandidates"])
        self.assertFalse(ir["experimentCandidates"][0]["executableOracle"])

    def test_runtime_observations_answer_resource_and_continuity_questions(self) -> None:
        analysis = self.analysis(
            "function route(request) { requireAuth(request); "
            "const normalized = customDecode(request); execute(normalized); }\n"
        )
        flow = next(
            row
            for row in analysis["relations"]
            if row.get("kind") == "validated-transformation-consumer"
        )
        fact_ids = [
            flow["validatedFact"],
            *flow["transformationFacts"],
            flow["consumerFact"],
        ]
        observations = [
            {
                "factId": fact_id,
                "objectIdentity": "request-1",
                "generation": 1,
                "principal": "anonymous",
                "process": "server-1",
                "runtime": "production",
                "resourceIdentity": "/admin",
            }
            for fact_id in fact_ids
        ]
        ir = build_semantic_ir(analysis, observations)
        path = ir["securityPaths"][0]
        self.assertEqual(path["resourceAgreement"]["status"], "agreed")
        self.assertEqual(path["continuity"]["status"], "preserved")


if __name__ == "__main__":
    unittest.main()
