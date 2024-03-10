package main

import data.kubernetes

# Helper rule to check if a container has both limits and requests set for CPU and memory
has_resource_limits(container) {
    container.resources.limits.cpu
    container.resources.limits.memory
    
    # container.resources.requests.cpu
    # container.resources.requests.memory
}

# Violation rule for deployments without proper resource limits
violation[{"msg": msg, "name": name}] {
    some i
    
    kubernetes.is_deployment

    input.spec.template.spec.containers[i]
    container := input.spec.template.spec.containers[i]
    not has_resource_limits(container)
    
    name := input.metadata.name
    msg := sprintf("Deployment '%s' - Container '%s' does not have both CPU and memory limits and requests set.", [name, container.name])
}
