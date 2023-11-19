#!/bin/bash
ip_address_1="192.168.5.254"
ip_address_2="192.168.3.254"

get_interface_name () {
  local ip_address=$1
  interface_name=$(ip -o addr show | awk -v ip="$ip_address" '$0 ~ ip {print $2}')

  if [ -z "$interface_name" ]; then
    echo "Error: No interface found for IP address '$ip_address'."
    exit 1
  fi
  echo $interface_name

}

inter_1=$(get_interface_name "$ip_address_1")
inter_2=$(get_interface_name "$ip_address_2")

sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o $inter_1 -i $inter_2 -j ACCEPT
sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o $inter_2 -i $inter_1 -j ACCEPT
echo "Routing is set"

