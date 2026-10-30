.PHONY: install web-install run api web build serve demo demo-record test clean help attack-index eval-rag eval-rag-agent

VENV := .venv
PY := $(VENV)/bin/python
WEB := web

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Create the venv (Python 3.12) and install Python dependencies
	uv venv --python 3.12 $(VENV)
	uv pip install --python $(VENV) -r requirements-dev.txt
	@echo "→ Copy .env.example to .env and set your DeepSeek key."

web-install:  ## Install the React frontend dependencies (npm)
	cd $(WEB) && npm install

run:  ## Analyze a domain from the CLI:  make run DOMAIN=example.com
	$(PY) main.py $(DOMAIN)

api:  ## Run the FastAPI API (frontend backend) on port 8000
	$(VENV)/bin/uvicorn api:app --reload --port 8000

web:  ## Run the React frontend in dev (Vite, port 5173) — proxies /api to 8000
	cd $(WEB) && npm run dev

build:  ## Build the React frontend into web/dist (then served by the API)
	cd $(WEB) && npm run build

serve: build  ## Build the frontend, then serve everything (frontend + API) on port 8000
	$(VENV)/bin/uvicorn api:app --port 8000

demo:  ## Build the backend-less demo (replayed recordings) into web/dist-demo + web/osintllm-demo.zip
	$(PY) scripts/demo_data.py export
	cd $(WEB) && npm run build:demo
	cd $(WEB)/dist-demo && rm -f ../osintllm-demo.zip && zip -qr ../osintllm-demo.zip .
	@echo "→ Upload the content of web/dist-demo/ (or web/osintllm-demo.zip) to any static host."

demo-record:  ## Record real analyses for the demo (LLM quota):  make demo-record TARGETS="wikipedia.org mozilla.org:email_security_posture"
	$(PY) scripts/demo_data.py record $(TARGETS)

test:  ## Run the test suite
	$(PY) -m pytest

eval:  ## Run the full eval harness (--replay, 15 domains x 3 reps): evals/results/
	$(PY) evals/run_eval.py

eval-quick:  ## Quick eval on a subset: make eval-quick DOMAINS="qapilot.com craigslist.org"
	$(PY) evals/run_eval.py --domains $(DOMAINS) --repetitions 1

eval-scenario:  ## Eval of one scenario: make eval-scenario SCENARIO=phishing_triage DOMAINS="..." [REPETITIONS=1]
	$(PY) evals/run_eval.py --scenario $(SCENARIO) --domains $(DOMAINS) --repetitions $(or $(REPETITIONS),1)

eval-adversarial:  ## Adversarial suite (prompt injection): evals/adversarial/results/
	$(PY) evals/run_adversarial.py

attack-index:  ## Rebuild the MITRE ATT&CK index (data/attack/, needs MISTRAL_API_KEY)
	$(PY) scripts/build_attack_index.py

eval-rag:  ## ATT&CK retrieval eval, offline replay of the committed embeddings: evals/rag/results/
	$(PY) evals/rag/run_retrieval_eval.py --offline

eval-rag-agent:  ## Agent-level ATT&CK eval, layer off then on (REAL LLM calls): make eval-rag-agent [DOMAINS="..."] [REPETITIONS=3]
	$(PY) evals/run_eval.py --attack-rag off --no-judge --no-detection --repetitions $(or $(REPETITIONS),3) $(if $(DOMAINS),--domains $(DOMAINS),)
	$(PY) evals/run_eval.py --attack-rag on --no-judge --no-detection --repetitions $(or $(REPETITIONS),3) $(if $(DOMAINS),--domains $(DOMAINS),)

clean:  ## Remove caches, reports and temporary files
	rm -rf .cache reports .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
