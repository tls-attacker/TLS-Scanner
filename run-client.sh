#!/bin/bash

docker kill $(docker ps -q)
docker run --shm-size 4g -m 8g --network host $1
