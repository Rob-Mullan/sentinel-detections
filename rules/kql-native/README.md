# Native KQL rules

Rules that don't fit Sigma (multi-table joins, complex aggregation, watchlists)
live here in the [Azure-Sentinel YAML format](https://github.com/Azure/Azure-Sentinel/wiki/Query-Style-Guide).
Required keys: `id`, `name`, `description`, `severity`, `query`, `tactics`.
They go through the same checks and deployment as Sigma rules.
