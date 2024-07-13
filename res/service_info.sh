# Service Node Count.
declare -A node_service_count

# Iterate through each service
for service in $(docker service ls --format '{{.Name}}'); do
  # Get running tasks for the service
  for node in $(docker service ps $service --filter "desired-state=running" --format '{{.Node}}'); do
    # Increment the count for the node
    ((node_service_count[$node]++))
  done
done

# Print the results
echo "Number of running services per node:"
echo
for node in "${!node_service_count[@]}"; do
  echo "Node: $node, Running Services: ${node_service_count[$node]}"
done
echo


# Each Service on and their tasks and their nodes.
for service in $(docker service ls --format '{{.Name}}'); do
  service_id=$(docker service ls --filter "name=$service" --format '{{.ID}}')
  echo "Service: $service (ID: $service_id)"
  docker service ps $service --filter "desired-state=running" --format 'Task ID: {{.ID}} | Task Name: {{.Name}} | Node: {{.Node}} | Status: {{.CurrentState}}'
  echo
done