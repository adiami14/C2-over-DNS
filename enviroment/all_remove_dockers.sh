#!/bin/bash
docker stop $(docker ps -aq)
docker rm -f $(docker ps -aq)
docker network rm $(docker network ls -q)
docker rmi $(docker images -a -q)


