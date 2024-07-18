#!/bin/bash

# Count chars of longest values.
max_name_length=0
max_id_length=0
max_mode_length=0
max_replicas_length=0
max_image_length=0
for service in $(docker service ls --format '{{.ID}}'); do

    # Get individual values to print out later.
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    service_id=$(docker service ls --filter id=$service --format 'ID: {{.ID}}')
    service_mode=$(docker service ls --filter id=$service --format 'Mode: {{.Mode}}')
    service_replicas=$(docker service ls --filter id=$service --format 'Replicas: {{.Replicas}}')
    service_image=$(docker service ls --filter id=$service --format 'Image: {{.Image}}')
    
    # Calculate the length of these values.
    name_length=${#service_name}
    id_length=${#service_id}
    mode_length=${#service_mode}
    replicas_length=${#service_replicas}
    image_length=${#service_image}
    
    # Update the maximum lengths if necessary.
    if (( name_length > max_name_length )); then
        max_name_length=$name_length
    fi
    if (( id_length > max_id_length )); then
        max_id_length=$id_length
    fi
    if (( mode_length > max_mode_length )); then
        max_mode_length=$mode_length
    fi
    if (( replicas_length > max_replicas_length )); then
        max_replicas_length=$replicas_length
    fi
    if (( image_length > max_image_length )); then
        max_image_length=$image_length
    fi
done

for service in $(docker service ls --format '{{.ID}}'); do
    service_name=$(docker service ls --filter id=$service --format '{{.Name}}')
    service_id=$(docker service ls --filter id=$service --format 'ID: {{.ID}}')
    service_mode=$(docker service ls --filter id=$service --format 'Mode: {{.Mode}}')
    service_replicas=$(docker service ls --filter id=$service --format 'Replicas: {{.Replicas}}')
    service_image=$(docker service ls --filter id=$service --format 'Image: {{.Image}}')
    print_info "$service_name" "$max_name_length" "$service_id" "$max_id_length" "$service_mode" "$max_mode_length" "$service_replicas" "$max_replicas_length" "$service_image" "$max_image_length" 
done
echo
echo