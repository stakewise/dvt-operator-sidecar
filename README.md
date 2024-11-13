# DVT-operator sidecar

DVT-Sidecar is a service which should be running on each DVT operator in DVT cluster.
Works in conjuction with [DVT-relayer](https://github.com/stakewise/dvt-relayer/).

DVT sidecar:

1. Loads DV keystores
2. Polls validator exits from Relayer
3. Pushes exit signature shares to Relayer on behalf of DVT operators.

## Run in docker

1. `cp .env.example .env`
2. Fill .env file with appropriate values
3. Run container

```shell
docker run \
-u $(id -u):$(id -g) \
--env-file .env \
-v $(pwd)/data:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/dvt-operator-sidecar:v0.4.2
```

## Development

### Setup

1. Install [poetry](https://python-poetry.org/)
2. `poetry install`
3. `cp .env.example .env`
4. Fill .env file with appropriate values

### Run

1. `poetry shell`
2. `export PYTHONPATH=.`
3. `python src/app.py`

### Testing

This section is about integration testing, when sidecar works in conjunction with DVT Relayer and Stakewise Operator.

Running the whole cluster of DVT sidecars locally may be cumbersome.
For testing purpose single sidecar may work on behalf of several DVT operators.
So there are 2 ways to initialize environment: one for production and another one for testing.

Example of production setup for Obol:

```ini
OBOL_KEYSTORES_DIR_TEMPLATE=node0/validator_keys
OBOL_NODE_INDEX=0
```

In testing setup you can parametrize keystores path so that single sidecar will be using multiple keystores:

```ini
OBOL_KEYSTORES_DIR_TEMPLATE=node{node_index}/validator_keys
OBOL_NODE_INDEXES=0,1,2,3
```

Example of production setup for SSV:

```ini
SSV_OPERATOR_KEY_FILE=encrypted_private_key.json
SSV_OPERATOR_PASSWORD_FILE=password.txt
SSV_OPERATOR_ID=123
```

In testing setup you can parametrize SSV operator key path.
So that sidecar will be acting on behalf of multiple SSV operators.

```ini
SSV_OPERATOR_KEY_FILE_TEMPLATE=operator-{operator_id}/encrypted_private_key.json
SSV_OPERATOR_PASSWORD_FILE_TEMPLATE=operator-{operator_id}/password.txt
SSV_OPERATOR_IDS=123,456
```
