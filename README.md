# DVT-operator sidecar

DVT-Sidecar is a service which should be running on each DVT operator in DVT cluster.
Works in conjuction with [DVT-relayer](https://github.com/stakewise/dvt-relayer/).
DVT-Sidecar provides exit signature share for given share index.

### Setup

1. Install [poetry](https://python-poetry.org/)
2. `poetry install`
3. `cp .env.example .env`
4. Fill .env file with appropriate values

### Run

1. `poetry shell`
2. `export PYTHONPATH=.`
3. `python src/app.py`
