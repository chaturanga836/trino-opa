package trino

import future.keywords.if
import future.keywords.in

default allow := false

# 1. Global Admins can see everything
allow if {
    "trino_admin" in input.context.groups
}

# 2. Dynamic Tenant Rule: 
# Access is allowed if the schema name is exactly the same as one of the user's groups
allow if {
    # Extract the schema being accessed
    requested_schema := input.action.resource.schema.name
    
    # Check if that schema name exists in the user's list of groups
    requested_schema in input.context.groups
}