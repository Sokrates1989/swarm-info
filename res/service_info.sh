for service in $(docker service ls --format '{{.Name}}'); do
  echo "Service: $service"
  docker service ps $service --format 'Task: {{.Name}} | Node: {{.Node}} | Status: {{.CurrentState}}'
  echo
done