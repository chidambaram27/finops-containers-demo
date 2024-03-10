package main

import data.kubernetes

name := input.metadata.name

required_deployment_labels := {
      "app.kubernetes.io/name",
      "app.kubernetes.io/instance",
      "app.kubernetes.io/version",
      "app.kubernetes.io/component",
      "app.kubernetes.io/part-of",
      "app.kubernetes.io/managed-by",
}

find_missing_labels(labels) = missing {
    missing := {label |
        required_deployment_labels[label]
        not labels[label]
    }
}

deny[msg] {
	kubernetes.is_deployment
	
      labels := input.metadata.labels
      missing_labels := find_missing_labels(labels)
      
      count(missing_labels) > 0
      missing_labels_str := concat(", ", sort([label | label := missing_labels[_]]))
      
      msg := sprintf("%s is missing the following recommended labels: %s. See https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels for more information.", [name, missing_labels_str])
}