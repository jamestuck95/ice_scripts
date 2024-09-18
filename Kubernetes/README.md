
# Kubectl cheat sheet:

### Show all pods on the cluster
    kubectl get pods -o wide

### Target specific namespaces
> For example to target the kube-public namespace only you would use this command; kubectl get pods -o wide --namespace=kube-public
    --namespace=kube-public