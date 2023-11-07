#!/bin/bash
# set github token to pull private repos
# Can be created at https://github.com/settings/tokens
# (As of 2023-11-03) A fine grained token does not seem to work, a classical one is required with the "repo" permission
# Unfortunately, less permissions do not seem to work. Hopefully this will change in the future.

if [ "$1" = "run-with-credentials" ]; then
    # implementation detail:
    # only dump credentials if explicitly asked to
    # According to https://pythonspeed.com/articles/docker-build-secrets/ relying on docker secrets is the only way to go
    # this script is passed as a secret file to the docker build
    # in there it is called to start install-dependencies
    # it's a bit of a hack, but it works
    export GITHUB_TOKEN='TOKEN'
    shift;
    exec "$@"
fi

# we default to the standard branches, change to branch our commit number you need
# export ATTACKER_BRANCH='my_very_cool_feature_branch'
# You can also set 'N/A' to skip the dependency and rely on maven

export MODVAR_BRANCH='N/A'
export ASN1_BRANCH='master'
export X509_BRANCH='master'
export ATTACKER_BRANCH='master'
export SCANNER_BRANCH='master'
export CRAWLER_CORE_BRANCH='main'

docker_args=()
if [ "$1" != "use-cache" ]; then
    # default to not using cache, but sometimes it is useful (e.g. for testing purposes)
    # if "use-cache" is passed, we do not pass --no-cache
    docker_args+=(--no-cache)
fi

# for secrets we need to use docker compose instead of docker-compose
# https://stackoverflow.com/a/72280952
docker compose build "${docker_args[@]}"
