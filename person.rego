package httpapi.authz

default allow = false

# Get the JWT token
token := t {
    t := io.jwt.decode(input.api_token)
}

roles := r {
  some i
  r = token[i]["cognito:groups"]
}

is_admin {
  some i
  roles[i] == "Admins"
}

is_operator {
  some i
  roles[i] == "Operators"
}

allow {
  input.method == "GET"
  input.path = ["api", "persons"]
  is_admin
}

allow {
  input.method == "GET"
  input.path == ["api", "personslist"]
  is_operator
}

# allow {
#   input.method == "GET"
#   input.path = ["persons"]
#   is_operator
# }

allow {
  some username
  input.method == "GET"
  input.path = ["persons", username]
  is_admin
}

# allow {
#   some username
#   input.method == "PATCH"
#   input.path == ["persons", username]
#   is_admin
# }

# allow {
#   some username
#   input.method == "DELETE"
#   input.path == ["persons", username]
#   is_admin
# }
