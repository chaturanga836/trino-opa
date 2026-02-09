package trino

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# 1. Global Admins
# No change needed; this is the gold standard for superusers.
allow if {
    "trino_admin" in input.context.identity.groups
}

# 2. Metadata Discovery Rights
# Users need these to even see the catalog/schema list in DBeaver.
# We add "ExecuteQuery" because every action starts with a query request.
allow if {
    input.action.operation in ["FilterCatalogs", "FilterSchemas", "AccessCatalog", "ExecuteQuery"]
}

# 3. Dynamic Tenant Rule
# This is the "Zero-Edit" magic. 
# If a user is in Keycloak group "sales", they get access to schema "sales".
allow if {
    # Trino 479 passes the schema name here for table/schema operations
    requested_schema := input.action.resource.schema.schemaName
    
    # Check if the user has a group matching the schema name
    requested_schema in input.context.identity.groups
}

# 4. System Internal User
# Required so the Coordinator can talk to Workers and check node status.
allow if {
    input.context.identity.user == "trino"
}

# 5. Impersonation Guard (Fixes your DBeaver error)
# This allows a user to "be themselves" without triggering an impersonation deny.
allow if {
    input.action.operation == "ImpersonateUser"
    input.context.identity.user == input.action.targetUser
}
