| Tool | Exact | Partial | Missed | False pos. | Precision | Recall | F1 | Damage detected | Time |
|---|---|---|---|---|---|---|---|---|---|
| PhoenixCarve | 200 | 20 | 0 | 0 | 90.9% | 90.9% | 90.9% | 100.0% | 0.083s |
| Foremost | 160 | 20 | 40 | 0 | 88.9% | 72.7% | 80.0% | not supported | 0.191s |
| Scalpel | 100 | 120 | 0 | 143 | 27.6% | 45.5% | 34.3% | not supported | 0.108s |

| Tool | F1 (any byte offset) | F1 (sector aligned) |
|---|---|---|
| PhoenixCarve | 90.9% | 90.9% |
| Foremost | 80.0% | 80.0% |
| Scalpel | 34.1% | 34.5% |
