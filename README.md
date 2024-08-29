# DVT-operator sidecar

DVT-Sidecar is a service which should be running on each DVT operator in DVT cluster.
Works in conjuction with [DVT-relayer](https://github.com/stakewise/dvt-relayer/).

DVT sidecar:

1. Loads DV keystores
2. Polls validator exits from Relayer
3. Pushes exit signature shares to Relayer on behalf of DVT operators.

## Setup

1. Install [poetry](https://python-poetry.org/)
2. `poetry install`
3. `cp .env.example .env`
4. Fill .env file with appropriate values

## Run

1. `poetry shell`
2. `export PYTHONPATH=.`
3. `python src/app.py`

## Testing

Running the whole cluster of DVT sidecars locally may be cumbersome.
For testing purpose single sidecar may work on behalf of several DVT operators.
To do that you have to fill `SHARE_INDEXES` in sidecar's environment. For example:

```text
SHARE_INDEXES=1,2,3,4
```
