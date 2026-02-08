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
    # Extract the schema name from the resource
    requested_schema := input.action.resource.schema.schemaName
    
    # FIX: In newer Trino versions, groups are under context.identity.groups
    requested_schema in input.context.identity.groups
}