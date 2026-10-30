from __future__ import annotations

import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


class CodexSkillContractTests(unittest.TestCase):
    def test_codex_install_section_is_agent_facing(self) -> None:
        readme = (PROJECT / "README.md").read_text(encoding="utf-8")
        section = readme.split("### Load the skill in Codex", 1)[1].split(
            "### Start with only the program rules", 1
        )[0]
        self.assertNotIn("python", section.lower())
        self.assertIn("$krineon", section)
        self.assertIn("references/codex.md", section)

    def test_skill_routes_codex_to_native_adapter(self) -> None:
        skill = (PROJECT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/codex.md", skill)
        self.assertIn('fork_turns="none"', skill)
        self.assertIn("durable scheduler", skill)

    def test_codex_adapter_binds_every_collaboration_tool(self) -> None:
        adapter = (PROJECT / "references" / "codex.md").read_text(
            encoding="utf-8"
        )
        for tool in (
            "list_agents",
            "spawn_agent",
            "send_message",
            "followup_task",
            "interrupt_agent",
            "wait_agent",
        ):
            self.assertIn(f"`{tool}`", adapter)
        self.assertIn('`fork_turns="none"`', adapter)
        self.assertIn("cannot unlock dependencies", adapter)
        self.assertIn("fresh, distinct Codex identity", adapter)

    def test_openai_metadata_invokes_the_skill(self) -> None:
        metadata = (PROJECT / "agents" / "openai.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("$krineon", metadata)
        self.assertIn("independent Codex agents", metadata)


if __name__ == "__main__":
    unittest.main()
