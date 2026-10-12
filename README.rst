Zero-Trust Agent Identity
=========================

Reference implementation and experiment harness for principal-bound,
instance-bound, action-bound authorization and effect-closed authority
transitions for autonomous agents.

Authors
-------

Medhavee Upadhyaya and Gaurav Chaulagain

Requirements
------------

* Python 3.11 or newer. The recorded host runs used Python 3.12.14.
* Docker is required only for the optional E014 container-isolation pilot.
* The exact recorded environments are listed in ``experiments/environment.csv``.

Installation and tests
----------------------

From the repository root::

  python3 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -e .
  PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v

Experiment records
------------------

``experiments/experiment_registry.csv`` defines the seed set, case count,
endpoints, status, and limitations for E001 through E014. Each experiment
driver prints its accepted command-line arguments when invoked without
arguments. Except for E001, the standard form is::

  PYTHONPATH=src .venv/bin/python experiments/RUN_SCRIPT.py \
    SEED TRIALS experiments/runs/OUTPUT.csv

Create the local output directory before running an experiment::

  mkdir -p experiments/runs

The raw case files under ``experiments/runs/`` are intentionally excluded
from version control. The repository versions aggregate CSV outputs and the
scripts that generate them.

E011 through E013
-----------------

The confirmatory networked and self-healing runs use three deterministic
seeds::

  for seed in 104729 130363 155921; do
    PYTHONPATH=src .venv/bin/python experiments/run_networked_authority_faults.py \
      "$seed" 550 "experiments/runs/networked_authority_seed_${seed}.csv"
    PYTHONPATH=src .venv/bin/python experiments/run_self_healing_faults.py \
      "$seed" 420 "experiments/runs/self_healing_seed_${seed}.csv"
    PYTHONPATH=src .venv/bin/python experiments/run_self_healing_ablation.py \
      "$seed" 280 "experiments/runs/self_healing_ablation_seed_${seed}.csv"
  done

Regenerate the corresponding aggregate files::

  PYTHONPATH=src .venv/bin/python experiments/summarize_networked_authority_faults.py \
    experiments/networked_authority_summary.csv \
    experiments/runs/networked_authority_seed_104729.csv \
    experiments/runs/networked_authority_seed_130363.csv \
    experiments/runs/networked_authority_seed_155921.csv

  PYTHONPATH=src .venv/bin/python experiments/summarize_self_healing_faults.py \
    experiments/self_healing_summary.csv \
    experiments/runs/self_healing_seed_104729.csv \
    experiments/runs/self_healing_seed_130363.csv \
    experiments/runs/self_healing_seed_155921.csv

  PYTHONPATH=src .venv/bin/python experiments/summarize_self_healing_ablation.py \
    experiments/self_healing_ablation_summary.csv \
    experiments/runs/self_healing_ablation_seed_104729.csv \
    experiments/runs/self_healing_ablation_seed_130363.csv \
    experiments/runs/self_healing_ablation_seed_155921.csv

  PYTHONPATH=src .venv/bin/python experiments/summarize_self_healing_ablation_pairs.py \
    experiments/self_healing_ablation_pairwise_summary.csv \
    experiments/runs/self_healing_ablation_seed_104729.csv \
    experiments/runs/self_healing_ablation_seed_130363.csv \
    experiments/runs/self_healing_ablation_seed_155921.csv

E014 container-isolation pilot
------------------------------

E014 is a preliminary one-seed, eight-case Docker pilot. It uses separate
Linux containers, processes, network namespaces, and Docker-managed volumes
on one physical host. It is not a physical multi-host experiment.

Build and execute it with::

  docker build -f experiments/docker/e014.Dockerfile -t ztai-e014:artifact .
  PYTHONPATH=src .venv/bin/python experiments/run_container_authority_faults.py \
    130363 8 experiments/runs/container_authority_seed_130363.csv \
    ztai-e014:artifact
  PYTHONPATH=src .venv/bin/python experiments/summarize_container_authority_faults.py \
    experiments/container_authority_summary.csv \
    experiments/runs/container_authority_seed_130363.csv

Interpretation boundary
-----------------------

The aggregate files report exact counts and descriptive rates for the
registered deterministic cases. They are not independent random samples and
do not support population confidence intervals. Operational baselines are
explicit mechanism definitions in this codebase, not reimplementations of
the external systems cited in the manuscript.
