
# Kubectl cheat sheet:

### Show all pods on the cluster
    kubectl get pods -o wide

### Target specific namespaces
    --namespace=kube-public
    kubectl get pods -o wide --namespace=kube-public