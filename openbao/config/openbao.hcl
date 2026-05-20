ui            = true
disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "raft" {
  path    = "/openbao/data"
  node_id = "node1"
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"
