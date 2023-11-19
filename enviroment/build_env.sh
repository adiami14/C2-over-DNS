#!/bin/bash

check_and_build_image() {
    local image_name="$1"
    local dockerfile="$2"

    # Check if the image exists
    if [[ -z $(docker images -q $image_name) ]]; then
        # If the image doesn't exist, build it
        echo "$image_name image not found. Building..."
        docker build -t $image_name -f $dockerfile .
    else
        # If the image exists, print a message and continue
        echo "$image_name image already exists. Continuing..."
    fi
}

remove_container () {
    local name="$1"
    docker stop $name
    docker container rm $name
}

remove_all () {
    remove_container "$UB_CLIENT_NAME"
    remove_container "$UB_SERVER_NAME"
    remove_container "$AT_DOCK_NAME"
    remove_container "$DNS_DOCK_NAME"
    docker network rm $NETWORK_client
    docker network rm $NETWORK_server
}

UBUNTU_IMAGE="ubuntu_image"
UBUNTU_DOCKERFILE="Dockerfile.ubuntu"
UB_CLIENT_NAME="c2_client"
UB_SERVER_NAME="c2_server"

AUTH_DNS="authoritative-dns"
AUTH_DNS_DOCKERFILE="Dockerfile.authoritative"
AT_DOCK_NAME=$AUTH_DNS

DNS_IMAGE="pihole/pihole"
DNS_DOCKERFILE="Dockerfile.dns"
DNS_DOCK_NAME="dns_server"

NETWORK_client="DNS_client"
NETWORK_server="DNS_c2_server"

echo -e "\n\n\t1. Build the docker enviroment\n\t2. Remove containers\n\t3. Remove Containers and images\n\t4. Remove a specific docker"
read choise

case $choise in
    1 )
    check_and_build_image "$UBUNTU_IMAGE" "$UBUNTU_DOCKERFILE"
    check_and_build_image "$AUTH_DNS" "$AUTH_DNS_DOCKERFILE"
    check_and_build_image "$DNS_IMAGE" "$DNS_DOCKERFILE"

    docker network create --subnet=192.168.3.0/24 --gateway=192.168.3.254 $NETWORK_client
    docker network create --subnet=192.168.5.0/24 --gateway=192.168.5.254 $NETWORK_server
    
    docker run -d -it --name $AT_DOCK_NAME --network $NETWORK_client --ip 192.168.3.100 -p 8053:53/udp -p 2222:22 -v $(pwd)/../:/data $AUTH_DNS
    docker run -d -it --name $DNS_DOCK_NAME --network $NETWORK_client --ip 192.168.3.3 -p 5353:53/tcp -p 5352:53/udp -e ServerIP=192.168.3.3 -v $(pwd)/../:/data $DNS_IMAGE
    
    docker run -d -it --name $UB_CLIENT_NAME --network $NETWORK_client --ip 192.168.3.70 --dns 192.168.3.3 -v $(pwd)/../:/data $UBUNTU_IMAGE
    docker run -d -it --name $UB_SERVER_NAME --network $NETWORK_server --ip 192.168.5.70 -v $(pwd)/../:/data $UBUNTU_IMAGE

    ./set_routing.sh
    docker ps
    ;;
    2 )
    remove_all
    ;;
    3 )
    remove_all
    docker image rm $UBUNTU_IMAGE
    docker image rm $AUTH_DNS
    docker image rm $DNS_IMAGE
    ;;
    4 )
    docker container ls
    echo -e "\n\t choose a container"
    read container_name
    remove_container "$container_name"
    docker image rm "$container_name"
    ;;
esac

