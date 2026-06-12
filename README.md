# RECITALS – Explainer (preliminary)

## Overview

This component is a **preliminary prototype** for the RECITALS explainer for the first iteration: given a detected network threat (an IDS alert, optionally enriched with flow-level features), it calls an LLM to produce a human-readable explanation suitable for a Tier-1 SOC analyst.

This is **exploratory/feasibility work**, not a finished product. It currently supports:

- **Synthetic Suricata-style IDS alerts** covering common attack categories (exploit, scan/reconnaissance, web RCE, DoS, backdoor/C2).
- **NF-UNSW-NB15-v2**, a public NetFlow-based intrusion detection benchmark, used both via built-in synthetic flow examples and via direct CSV loading for real records.

No novel model or prompting technique is claimed, this wraps existing open LLMs served via an internal inference endpoint with prompt templates.

## Why an internal LLM endpoint?

To address data privacy concerns, all LLM inference is routed through an LLM deployment hosted on an **L3S internal server** ([interweb.l3s.uni-hannover.de](https://interweb.l3s.uni-hannover.de/)) rather than an external/third-party API. This keeps any data sent to the LLM within institutional infrastructure.

At this stage, the inputs to the LLM are drawn from **open-source benchmark datasets or synthetic examples only** — no real partner/operational data is used yet. Prompt engineering and the amount/type of context provided to the LLM are expected to evolve based on the specific requirements of use-case partners; this is work in progress.

## Two explanation "cases"

| Case | Input | Description |
|---|---|---|
| **Case 1** | Suricata rule match + source/destination IP only | Minimal-context explanation: what the rule means and why it fired. |
| **Case 2** | Suricata rule match + full NF-UNSW-NB15-v2 flow features | Richer explanation grounded in concrete flow statistics (byte/packet counts, duration, TCP flags, throughput, etc.), corroborating the rule match. |

## Two interfaces

| Interface | Cases supported | Description |
|---|---|---|
| **CLI** (`cli/threat_explainer.py`) | Case 1 and Case 2 | Command-line tool. Runs both cases on synthetic data by default, or Case 2 on a real NF-UNSW-NB15-v2 CSV with optional attack-type filtering. Can dump results to JSON. |
| **Web UI** (`webapp/flask_app.py` + `webapp/templates/index.html`) | Case 1 only | Flask app with a browser UI: pick a synthetic alert, pick an LLM model, edit the system/user prompt live, and view both the explanation and the exact request sent to the LLM (debug tab). |

The web UI is currently a Case 1 demo only; Case 2 (flow-feature-grounded explanations) is so far only available via the CLI.

## Repository structure

```
.
├── README.md
├── requirements.txt
├── cli/
│   └── threat_explainer.py      # Case 1 + Case 2, synthetic + CSV (NF-UNSW-NB15-v2)
└── webapp/
    ├── flask_app.py             # Flask web UI (Case 1)
    └── templates/
        └── index.html           # UI template for flask_app.py
```

## Setup

```bash
pip install -r requirements.txt
```

`requirements.txt` should include at minimum:
```
flask
openai
pandas
```

### LLM backend

Both the CLI and the web UI call an OpenAI-compatible chat completions endpoint:

```python
client = OpenAI(base_url="http://interweb.l3s.uni-hannover.de")
```

This points at an internal model-serving endpoint used for the RECITALS project. The `OPENAI_API_KEY` environment variable must be set before running either script:

```bash
export OPENAI_API_KEY="your-key-here"
```

**Do not hardcode API keys in source files.** Always set the key via the environment.

## Running the CLI

```bash
cd cli

# Run both cases on synthetic data
python threat_explainer.py

# Run Case 2 on a real NF-UNSW-NB15-v2 CSV, filtered to DoS, first 3 rows
python threat_explainer.py --csv NF-UNSW-NB15-v2.csv --attack DoS --n 3

# Run only Case 1, save results to JSON
python threat_explainer.py --case 1 --out results.json
```

CLI options:

| Flag | Description |
|---|---|
| `--csv PATH` | Path to NF-UNSW-NB15-v2 CSV (enables CSV mode for Case 2) |
| `--attack NAME` | Filter CSV rows by attack label (e.g. `DoS`, `Exploits`, `Worms`) |
| `--n INT` | Number of CSV rows to explain (default: 3) |
| `--case 1\|2\|all` | Which case to run (default: `all`) |
| `--out PATH` | Write results to a JSON file |

## Running the web UI

```bash
cd webapp
python flask_app.py
```

Then open `http://localhost:5000` (or the port configured in `flask_app.py`, currently `5002`).

In the UI you can:
1. Select one of the synthetic Suricata alerts.
2. Select an LLM model from the configured list.
3. Adjust the max output tokens.
4. Edit the auto-generated system/user prompts before sending.
5. View the generated explanation, plus a debug view of the exact prompt sent and the raw response metadata.

## Data sources

- **Synthetic Suricata alerts**: hand-crafted examples covering exploit, reconnaissance, web RCE, DoS, and backdoor/C2 attack types, with realistic rule syntax (`msg`, `content`, `classtype`, `sid`, etc.).
- **NF-UNSW-NB15-v2** [1, 2]: a NetFlow-based reformulation of the UNSW-NB15 intrusion detection dataset, used as a benchmark for Case 2. The dataset itself is not included in this repository; download it separately (see links below) and pass its path via `--csv`.

## Known limitations / TODO

- The model list in `webapp/flask_app.py` (`qwen3.5:27b`, `llama3.3:70b`, `llama4:scout`, `gemma4:31b`) should be reconciled with the models actually available on the `interweb.l3s.uni-hannover.de` endpoint used by the CLI (`llama3.3:70b`, `gemma2:9b`) before demos.
- Case 2 (flow-feature-grounded explanations) is not yet exposed in the web UI.
- This is a preliminary prototype intended to validate the explainer pipeline end-to-end before integration with real RECITALS network telemetry; prompts, model choices, and UI are expected to change.

## References

[1] Sarhan, M., Layeghy, S., & Portmann, M. (2022). Towards a standard feature set for network intrusion detection system datasets. *Mobile Networks and Applications*, 27(1), 357-370.

[2] ALzaher, F. J., & AlJarullah, A. (2025). Intrusion Detection Using Machine Learning and Deep Learning. *International Journal of Advanced Computer Science & Applications*, 16(8).

## Dataset links

- NF-UNSW-NB15-v2 (UQ eSpace): https://espace.library.uq.edu.au/view/UQ:ffbb0c1
- NF-UNSW-NB15-v2 (Kaggle mirror): https://www.kaggle.com/datasets/dhoogla/nfunswnb15v2

## LLM endpoint

- L3S internal LLM deployment: https://interweb.l3s.uni-hannover.de/
