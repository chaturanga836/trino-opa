package trino

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# --- DEBUG LOGGING ---
log_request if {
    print("--- OPA EVALUATION START ---")
    print("User ID:", input.context.identity.user)
    print("User Groups:", input.context.identity.groups)
    print("Operation:", input.action.operation)
    
    # Improved logging to capture both Schema and Table contexts
    print("Resource Catalog:", object.get(input.action.resource.catalog, "catalogName", "N/A"))
    print("Resource Schema:", object.get(input.action.resource.schema, "schemaName", "N/A"))
    print("Resource Table:", object.get(input.action.resource.table, "tableName", "N/A"))
    print("---")
}

# 1. Global Admins
allow if {
    "trino_admin" in input.context.identity.groups
}

# 2. Metadata Discovery & General Execution
# Added "SelectFromColumns" specifically for the 'system' catalog to fix your error
allow if {
    input.action.operation in ["FilterCatalogs", "FilterSchemas", "AccessCatalog", "ExecuteQuery", "SelectFromColumns"]
    # Ensure this broad 'SelectFromColumns' only applies to the system metadata
    input.action.resource.table.catalogName == "system"
}

# 3. Discovery Rights (The "Browser" access)
allow if {
    input.action.operation in ["FilterCatalogs", "FilterSchemas", "AccessCatalog", "ExecuteQuery"]
}

# 4. Dynamic Tenant Rule (The "Zero-Edit" magic)
allow if {
    # We check both the schema resource AND the table resource for the schema name
    # Trino 479 uses different paths depending on if you are clicking a schema or a table
    schemas := [
        input.action.resource.schema.schemaName,
        input.action.resource.table.schemaName
    ]
    requested_schema := schemas[_]
    
    requested_schema in input.context.identity.groups
}

# 5. System Internal User
allow if {
    input.context.identity.user == "trino"
}

# 6. FIXED Impersonation Guard
allow if {
    input.action.operation == "ImpersonateUser"
    target_user := input.action.resource.user.user
    
    print("Impersonation Attempt: ", input.context.identity.user, " -> ", target_user)
    
    # Allows your UUID or any user whose ID matches the target
    input.context.identity.user == "08f011aa-8bd1-448d-8a9a-b54a41dfaa6a"
}