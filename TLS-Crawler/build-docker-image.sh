#!/bin/bash
# Set github token to pull private repos
# They can be created at https://github.com/settings/tokens
# Fine grained tokens need the Repository>Contents (read-only suffices) permission and need to be created using the resource owner set to tls-attacker.
# Classical tokens require the "repo" permission.

if [ "$1" = "run-with-credentials" ]; then
    # implementation detail:
    # only dump credentials if explicitly asked to
    # According to https://pythonspeed.com/articles/docker-build-secrets/ relying on docker secrets is the only way to go
    # this script is passed as a secret file to the docker build
    # in there it is called to start install-dependencies
    # it's a bit of a hack, but it works
    export GITHUB_TOKEN='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'
    shift;
    exec "$@"
fi

# we default to relying on maven for most dependencies, change to the branch or commit hash you need
# export ATTACKER_BRANCH='my_very_cool_feature_branch'
# NB: The version of the dependency must match the version in the pom.xml, otherwise maven will again use a remote

export MODVAR_BRANCH='N/A'
export ASN1_BRANCH='N/A'
export X509_BRANCH='N/A'
export ATTACKER_BRANCH='N/A'
export SCANNER_BRANCH='webapp_partial'
export SCANNER_CORE_BRANCH='webapp_partial'
export CRAWLER_CORE_BRANCH='webapp_partial'

docker_args=()
if [ "$1" != "use-cache" ]; then
    # default to not using cache, but sometimes it is useful (e.g. for testing purposes)
    # if "use-cache" is passed, we do not pass --no-cache
    docker_args+=(--no-cache)
fi

# for secrets we need to use docker compose instead of docker-compose
# https://stackoverflow.com/a/72280952
docker compose build "${docker_args[@]}"
