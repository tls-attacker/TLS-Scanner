#!/bin/bash -e

function clone_install_dependency {
    # $1: repo name
    # $2: branch name
    if [ "$2" == "N/A" ]; then
        echo "Skipping $1 as branch is set to N/A"
        return
    fi

    echo "Cloning $1 with git reference $2"
    git clone "https://git:$GITHUB_TOKEN@github.com/tls-attacker/$1.git" || (echo "Failed to clone $1 - check your GITHUB_TOKEN inside build-docker-image.sh"; return 1)
    cd "$1" || (echo "Failed to cd into $1"; return 2)
    git checkout "$2"
    mvn clean install -DskipTests -Dmaven.javadoc.skip=true
}

# install dependencies
clone_install_dependency ModifiableVariable "${MODVAR_BRANCH:master}"
clone_install_dependency ASN.1-Tool-Development "${ASN1_BRANCH:master}"
clone_install_dependency X509-Attacker-Development "${X509_BRANCH:master}"
clone_install_dependency TLS-Attacker-Development "${ATTACKER_BRANCH:master}"
clone_install_dependency TLS-Scanner-Development "${SCANNER_BRANCH:master}"
