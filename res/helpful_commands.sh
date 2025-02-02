#!/bin/bash

# Get the directory of the script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# The space until the colon to align all output info to.
output_tab_space=30 

# Global functions.
source "$SCRIPT_DIR/functions.sh"

# Parse command-line options.
output_type="single_without_menu"
while getopts ":m" opt; do
  case $opt in
    m)
      output_type="single_with_menu"
      ;;
    \?)
      echo -e "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo -e "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done


# Helpful commands.
echo
echo
echo
echo "Helpful docker commands (bash $MAIN_DIR/get_info.sh --commands (--menu) )"
echo
echo
echo "Basic swarm info"
echo
printf "%-${output_tab_space}s: %s\n" "View All Nodes" "docker node ls"
printf "%-${output_tab_space}s: %s\n" "View Labels of Nodes" "docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}"
printf "%-${output_tab_space}s: %s\n" "Join Token Manager" "docker swarm join-token manager"
printf "%-${output_tab_space}s: %s\n" "Join Token Worker" "docker swarm join-token worker"
echo
echo
echo
echo "Labels"
echo
printf "%-${output_tab_space}s: %s\n" "View Labels of Nodes" "docker node ls -q | xargs docker node inspect --format '{{ .ID }} [{{ .Description.Hostname }}]: {{ .Spec.Labels }}"
printf "%-${output_tab_space}s: %s\n" "Set Label" "docker node update --label-add <KEY>=<VALUE> <NODE_ID>"
printf "%-${output_tab_space}s: %s\n" "Remove Label" "docker node update --label-rm <KEY> <NODE_ID>"
echo
echo
echo
echo "Local Node"
echo
printf "%-${output_tab_space}s: %s\n" "View Docker Version" "docker --version"
printf "%-${output_tab_space}s: %s\n" "View Local Containers" "docker ps"
printf "%-${output_tab_space}s: %s\n" "View Local Volumes" "docker volume ls"
printf "%-${output_tab_space}s: %s\n" "Inspect Volume" "docker volume inspect <VOLUMENAME>"
echo
echo
echo
echo "Networks"
echo
printf "%-${output_tab_space}s: %s\n" "View All Networks" "docker network ls"
printf "%-${output_tab_space}s: %s\n" "Create Network" "docker network create --driver overlay --attachable <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Get Info" "docker network inspect <NETWORKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Network" "docker network rm <NETWORKNAME>"
echo
echo
echo
echo "Secrets"
echo
printf "%-${output_tab_space}s: %s\n" "View All Secrets" "docker secret ls"
printf "%-${output_tab_space}s: %s\n" "Create Secret" "vi secret.txt    (then insert secret and save file)"
printf "%${output_tab_space}s  %s\n" "" "docker secret create <SECRETNAME> secret.txt"
printf "%${output_tab_space}s  %s\n" "" "rm secret.txt"
printf "%-${output_tab_space}s: %s\n" "Inspect Secret" "docker secret inspect --pretty <SECRETNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Secret" "docker secret rm <SECRETNAME>"
echo
echo
echo
echo "Services"
echo
printf "%-${output_tab_space}s: %s\n" "View All Services" "docker service ls"
printf "%-${output_tab_space}s: %s\n" "Get Information" "docker service ps <SERVICENAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read Logs" "docker service logs <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Inspect Service" "docker service inspect <SERVICENAME> --pretty"
printf "%-${output_tab_space}s: %s\n" "Remove Service" "docker service rm <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Force Service Restart" "docker service update --force <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Service Node change (temp)" "docker service update --constraint-add 'node.hostname == <HOSTNAME>' <SERVICENAME>"
printf "%${output_tab_space}s  %s\n" "" "docker service update --constraint-rm 'node.hostname == <HOSTNAME>' <SERVICENAME>"
printf "%-${output_tab_space}s: %s\n" "Scale Service (1)" "docker service scale <SERVICENAME>=<AMOUNT_REPLICAS>"
printf "%-${output_tab_space}s: %s\n" "Scale Service (2)" "docker service update --replicas=<AMOUNT_REPLICAS> <SERVICENAME>"
echo
echo
echo
echo "Stacks"
echo
printf "%-${output_tab_space}s: %s\n" "View All Stacks" "docker stack ls"
printf "%-${output_tab_space}s: %s\n" "View Services of Stack" "docker stack services <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Deploy Stack" "docker stack deploy -c <DEPLOYCONFIG> <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Deploy Stack using .env" "docker stack deploy -c <(docker-compose -f <DEPLOYCONFIG> config) <STACKNAME>"
printf "%-${output_tab_space}s: %s\n" "Remove Stack" "docker stack rm <STACKNAME>"
echo
echo
echo
echo "Troubleshooting"
echo
printf "%-${output_tab_space}s: %s\n" "Get information" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Read logs" "docker service logs <SERVICE_NAME>"
echo 
echo "Enter container, if further information is needed"
printf "%-${output_tab_space}s: %s\n" "Determine Node" "docker service ps <SERVICE_NAME> --no-trunc"
printf "%-${output_tab_space}s: %s\n" "Enter node" "ssh into node (Putty or alike)"
printf "%-${output_tab_space}s: %s\n" "Get container ID" "docker ps"
printf "%-${output_tab_space}s: %s\n" "(Optional) Read container logs" "docker logs <CONTAINER_ID>"
printf "%-${output_tab_space}s: %s\n" "Enter container (shell)" "docker exec -it <CONTAINER_ID> /bin/sh"
printf "%-${output_tab_space}s: %s\n" "Enter container (bash)" "docker exec -it <CONTAINER_ID> /bin/bash"
echo
echo


# Go on after showing desired info based on output type.
case $output_type in
    single_without_menu)
        : # No operation
        ;;
    single_with_menu)
        wait_for_user
        display_menu
        ;;
esac

