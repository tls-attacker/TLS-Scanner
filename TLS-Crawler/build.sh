# set at least git username and token (direct password authentication got disabled in 2021)
export GIT_USR='username'
export GIT_PWD='token'

# we default to the standard branches, change to branch our commit number you need
# export ATTACKER_BRANCH='my_very_cool_feature_branch'
export MODVAR_BRANCH='master'
export ASN1_BRANCH='master'
export X509_BRANCH='master'
export ATTACKER_BRANCH='master'
export SCANNER_BRANCH='master'

docker-compose build --no-cache
