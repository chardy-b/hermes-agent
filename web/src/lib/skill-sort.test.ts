import { describe, expect, it } from "vitest";
import type { SkillInfo } from "@/lib/api";
import { sortSkills } from "@/lib/skill-sort";

const skills: SkillInfo[] = [
  { name: "beta", description: "", category: "", enabled: true, character_count: 100, call_count: 5 },
  { name: "alpha", description: "", category: "", enabled: true, character_count: 100, call_count: 2 },
  { name: "gamma", description: "", category: "", enabled: true, character_count: 25, call_count: 5 },
];

describe("sortSkills", () => {
  it("sorts names alphabetically", () => {
    expect(sortSkills(skills, "name").map((skill) => skill.name)).toEqual([
      "alpha",
      "beta",
      "gamma",
    ]);
  });

  it("sorts size and call frequency descending with stable alphabetical ties", () => {
    expect(sortSkills(skills, "size").map((skill) => skill.name)).toEqual([
      "alpha",
      "beta",
      "gamma",
    ]);
    expect(sortSkills(skills, "calls").map((skill) => skill.name)).toEqual([
      "beta",
      "gamma",
      "alpha",
    ]);
  });

  it("does not mutate the API result", () => {
    const original = skills.map((skill) => skill.name);
    sortSkills(skills, "calls");
    expect(skills.map((skill) => skill.name)).toEqual(original);
  });

  it("uses exact deterministic name ordering for metric ties", () => {
    const composed = { ...skills[0], name: "é", call_count: 9 };
    const decomposed = { ...skills[0], name: "é", call_count: 9 };
    const expected = ["é", "é"];

    expect(sortSkills([composed, decomposed], "calls").map((skill) => skill.name)).toEqual(expected);
    expect(sortSkills([decomposed, composed], "calls").map((skill) => skill.name)).toEqual(expected);
  });
});