import type { SkillInfo } from "@/lib/api";

export type SkillSort = "name" | "size" | "calls";

function compareNames(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function sortSkills(skills: SkillInfo[], sortBy: SkillSort): SkillInfo[] {
  return [...skills].sort((a, b) => {
    const metricDifference =
      sortBy === "size"
        ? b.character_count - a.character_count
        : sortBy === "calls"
          ? b.call_count - a.call_count
          : 0;
    return metricDifference || compareNames(a.name, b.name);
  });
}