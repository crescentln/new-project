# Ruleset Pipeline (Public Snapshot)

此目录在公开仓库中仅保留构建脚本与发布产物所需配置。

## 可见性说明

- 详细设计与运维说明已迁移到私有文档仓库，仅仓库所有者可见。
- 公开仓库仅用于发布 OpenClash / Surge / Stash 可抓取规则文件。
- 私有说明仓库：`crescentln/Project_G_PrivateDocs`（private）。

## 公开产物目录

- `dist/openclash/`: OpenClash YAML 主入口与拆分产物
- `dist/surge/`: Surge list 主入口与拆分产物
- `dist/stash/`: Stash classical 主入口，以及 `domainset` / `ipcidr` / `classical` 拆分产物
