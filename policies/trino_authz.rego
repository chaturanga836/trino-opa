package trino

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# 1. FIXED: Global Admins (Added .identity)
allow if {
    "trino_admin" in input.context.identity.groups
}

# 2. NEW: Discovery Rights
# Users must be allowed to "see" the system hierarchy to reach their schemas.
allow if {
    input.action.operation in ["FilterCatalogs", "FilterSchemas", "AccessCatalog"]
}

# 3. Dynamic Tenant Rule
allow if {
    # In Trino 479, schemaName is the correct field
    requested_schema := input.action.resource.schema.schemaName
    
    # Check if that schema name exists in the user's groups
    requested_schema in input.context.identity.groups
}

# 4. System internal user (Critical for cluster health)
allow if {
    input.context.identity.user == "trino"
}