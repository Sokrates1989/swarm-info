#!/bin/bash

## List of Networks ##
echo "List of Networks:"

# Count chars of longest values.
max_name_length=0
max_id_length=0
max_driver_length=0
for network in $(docker network ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    network_name=$(docker network ls --filter id=$network --format '{{.Name}} ')
    network_id=$(docker network ls --filter id=$network --format 'ID: {{.ID}}')
    network_driver=$(docker network ls --filter id=$network --format 'Driver: {{.Driver}}')

    # Calculate the length of these values.
    name_length=${#network_name}
    id_length=${#network_id}
    driver_length=${#network_driver}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( driver_length > max_driver_length )); then
        max_driver_length=$driver_length
    fi
done

for network in $(docker network ls --format '{{.ID}}'); do
    network_name=$(docker network ls --filter id=$network --format '{{.Name}} ')
    network_id=$(docker network ls --filter id=$network --format 'ID: {{.ID}}')
    network_driver=$(docker network ls --filter id=$network --format 'Driver: {{.Driver}}')
    print_info "$network_name" "$max_name_length" "$network_id" "$max_id_length" "$network_driver" "$max_driver_length"
done