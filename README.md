# Project_G Ruleset Distribution

本仓库为公开发布仓库，仅用于发布 OpenClash / Surge / Stash 可直接抓取的规则产物。

## 可见性说明

- 详细说明文档、策略设计说明、维护操作手册：已迁移到私有仓库，仅仓库所有者可见。
- 本公开仓库不再发布上述详细说明内容。
- 私有说明仓库：`crescentln/Project_G_PrivateDocs`（private）。
- 每周自动更新流程保留，用于持续更新规则产物。

## 兼容性说明

- 现有 OpenClash 与 Surge 规则 URL 保持不变。
- 新增 Stash 专用产物路径，不影响现有 OpenClash / Surge 抓取。
- Raw Base（不变）：`https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist`

## 常用入口

- OpenClash `reject`: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject.yaml`
- OpenClash `direct`: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/direct.yaml`
- Surge `reject`: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject.list`
- Surge `direct`: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/direct.list`
- Stash `reject`（classical 主入口）: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/stash/reject.list`
- Stash `direct`（classical 主入口）: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/stash/direct.list`
- 推荐 Stash 模板（classical 兼容入口）: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/recommended_stash.yaml`
- 推荐 Stash 模板（Native 优化入口）: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/recommended_stash_native.yaml`
- Stash 原生拆分入口示例：
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/stash/domainset/direct.txt`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/stash/ipcidr/direct.txt`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/stash/classical/direct.list`
