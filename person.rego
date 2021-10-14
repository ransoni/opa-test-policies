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

allow {
  some username
  input.method == "GET"
  input.path = ["persons", username]
  is_admin
}

# bob is alice's manager, and betty is charlie's.
subordinates = {"alice": [], "charlie": [], "bob": ["alice"], "betty": ["charlie"]}

hr = [
  "betty",
]

# Allow users to get their own info.
allow {
  some username
  input.method == "GET"
  input.path = ["person", username]
  input.user == username
}

# Allow managers to get their subordinates' info.
allow {
  some username
  input.method == "GET"
  input.path = ["person", username]
  subordinates[input.user][_] == username
}

allow {
  input.method == "GET"
  input.path = [ "person", _ ]
  input.user == hr[_]
}
