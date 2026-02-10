package trino

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# --- DEBUG LOGGING ---
# This rule always "runs" and prints to OPA logs without affecting the result
log_request if {
    print("--- OPA EVALUATION START ---")
    print("User ID:", input.context.identity.user)
    print("User Groups:", input.context.identity.groups)
    print("Operation:", input.action.operation)
    
    # Safely try to print schema if it exists in the request
    print("Target Schema:", object.get(object.get(input.action.resource, "schema", {}), "schemaName", "N/A"))
    print("---")
}

# 1. Global Admins
allow if {
    "trino_admin" in input.context.identity.groups
}

# 2. Metadata Discovery Rights
allow if {
    input.action.operation in ["FilterCatalogs", "FilterSchemas", "AccessCatalog", "ExecuteQuery"]
}

# 3. Dynamic Tenant Rule
allow if {
    requested_schema := input.action.resource.schema.schemaName
    requested_schema in input.context.identity.groups
}

# 4. System Internal User
allow if {
    input.context.identity.user == "trino"
}

# 5. FIXED Impersonation Guard
# Based on your logs, we check the resource.user.user path
allow if {
    input.action.operation == "ImpersonateUser"
    target_user := input.action.resource.user.user
    
    # Logging the impersonation attempt
    print("Impersonation Attempt: ", input.context.identity.user, " -> ", target_user)
    
    # Logic: Allow if user is your UUID
    input.context.identity.user == "08f011aa-8bd1-448d-8a9a-b54a41dfaa6a"
}