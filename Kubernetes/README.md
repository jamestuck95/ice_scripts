
# Kubectl cheat sheet:

### Show all pods on the cluster
    kubectl get pods -o wide

### Target specific namespaces
**For example to view all pods in the kube-public namespace only you would use this command; _kubectl get pods -o wide --namespace=kube-public_**
    
    --namespace=kube-public

### Get all kubernetes services
    kubectl get service

### Get descriptions of commands
Kubectl's version of get-help in powershell
    
    kubectl explain pods

### Changes the replicaset value for the service
    kubectl scale deployment hello-world-rest-api --replicas=3

### Get kubernetes events - sorted by time
    kubectl get events --sort-by=.metadata.creationTimestamp

### Delete all kubernetes services with the label hello-world-rest-api
    kubectl.exe delete all -l app=hello-world-rest-api
    