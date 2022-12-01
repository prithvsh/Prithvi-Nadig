package system


import future.keywords.contains
import future.keywords.if
import future.keywords.in


operations := {"CREATE", "UPDATE"}


#deny unconfined
deny contains msg if{        operations[input.request.operation]        input.request.kind.kind == "Pod"        some container in input.request.object.spec.containers        container.securityContext.seccompProfile.type == "Unconfined"        msg := "Unconfined security context, denied!"
}


#deny secret access in pods
deny contains msg if{        operations[input.request.operation]        input.request.kind.kind == "Pod"        some volume in input.request.object.spec.volumes        volume.secret        msg := "secret access detecrted, denied!"
}


#deny hostpath access
deny contains msg if{        operations[input.request.operation]        input.request.kind.kind == "Pod"        some volume in input.request.object.spec.volumes        volume.hostPath        msg := "hostPath exists, access to host volumes, denied!"
}


#deny auto mounting at pod creation (including default)
deny contains msg if{        operations[input.request.operation]        input.request.kind.kind == "Pod"        input.request.spec.automountServiceAccountToken == "true"        msg := "Automount service active, denied"
}


#deny automounting indevidual request
deny contains msg if{        input.request.kind.kind == "ServiceAccount"        input.request.automountServiceAccountToken == "true"        msg := "Automount service active, denied"
}


#deny role binding
deny contains msg if{        input.request.kind.kind == "RoleBinding"        input.request.roleRef.name == "cluster-admin"        msg := "Role binding is set as Cluster-admin, denied"
}


#deny cluster role binding
deny contains msg if{        input.request.kind.kind == "ClusterRoleBinding"        input.request.roleRef.name == "cluster-admin"        msg := "Cluster Role binding is set as Cluster-admin, denied"
}


#deny if user context is present, but set to 0 (root)
deny contains msg if {        operations[input.request.operation]        input.request.object.spec.securityContext.runAsUser == 0        msg := "Deployment is set with root user security context"
}
deny contains msg if {        operations[input.request.operation]        input.request.object.spec.securityContext.runAsGroup == 0        msg := "Deployment is set with root group security context"
}
deny contains msg if {        operations[input.request.operation]        input.request.object.spec.securityContext.fsGroup == 0        msg := "Deployment is set with root fs group security context"
}


# deny if security context doesnt exist, as the default is root
deny contains msg if {        operations[input.request.operation]        input.request.object.spec.securityContext == {}        msg := "no security context set, default is root, denied"
}


#deny if no limit is present in create yaml
deny contains msg if {        operations[input.request.operation]        some container in input.request.object.spec.containers        not container.resources.limits.cpu

       msg := "container has no CPU limits set to it"
}
deny contains msg if {        operations[input.request.operation]        some container in input.request.object.spec.containers        not container.resources.limits.memory

       msg := "container has no memory limits set to it"
}


main = {    "apiVersion": "admission.k8s.io/v1",    "kind": "AdmissionReview",    "response": response,
}


reason = concat(", ", deny)


# for requests without uid
default response = {    "uid": "missing-uid",    "allowed": true,
}


# allowed
response = r {    reason == ""    r := {        "uid": input.request.uid,        "allowed": true,    }
}


# denied
response = r {    reason != ""    r := {        "uid": input.request.uid,        "allowed": true,        "status": {"reason": reason},    }
}



