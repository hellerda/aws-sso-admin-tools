# AWS-SSO-ADMIN Command Reference

## NAME

**aws-sso-admin** - Tools for managing AWS Identity Center (formerly AWS SSO)

## SYNOPSIS

```
aws-sso-admin [--profile PROFILE] [--region REGION] [-j|--json-only] COMMAND [OPTIONS]
```

## DESCRIPTION

The **aws-sso-admin** command-line tool provides a comprehensive interface for managing AWS IAM Identity Center resources including users, groups, permission sets, account assignments, and applications.

This tool supports 76 commands organized into 8 functional categories, providing both human-readable and machine-readable (JSON) output formats.

## GLOBAL OPTIONS

**--profile** *PROFILE*
: AWS profile to use from ~/.aws/credentials or ~/.aws/config

**--region** *REGION*
: AWS region to use (overrides AWS_REGION and AWS_DEFAULT_REGION environment variables)

**-j**, **--json-only**
: Output JSON only (machine-readable format). By default, commands produce human-readable output.

## AUTHENTICATION

The tool uses the standard AWS credential chain in the following order:

1. Explicit profile via **--profile** flag
2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
3. AWS credentials file (~/.aws/credentials)
4. AWS config file (~/.aws/config)
5. IAM role (when running on EC2/ECS/Lambda)

## ENVIRONMENT

**LOGLEVEL**
: Set logging level: CRITICAL, ERROR, WARNING, INFO, DEBUG (default: CRITICAL)

**AWS_REGION**, **AWS_DEFAULT_REGION**
: Default AWS region if --region not specified

**AWS_PROFILE**
: Default AWS profile if --profile not specified

**AWS_ACCESS_KEY_ID**, **AWS_SECRET_ACCESS_KEY**, **AWS_SESSION_TOKEN**
: AWS credentials for authentication

## COMMAND CATEGORIES

The commands are organized into 8 functional categories:

### 1. Resource Lookup (15 commands)
- lookup-account-name
- lookup-account-id
- lookup-ou-name
- lookup-ou-id
- lookup-ou-arn
- lookup-user-name
- lookup-user-id
- lookup-group-name
- lookup-group-id
- lookup-ps-name
- lookup-ps-arn
- lookup-app-name
- lookup-app-arn
- lookup-tti-name
- lookup-tti-arn

### 2. User and Group Management (17 commands)
- create-group
- delete-group
- describe-group
- list-groups
- describe-user
- create-users
- delete-users
- get-users
- list-users
- create-group-membership
- create-group-memberships
- get-group-membership
- get-group-memberships
- delete-group-membership
- delete-group-memberships
- list-group-memberships
- list-all-group-memberships-for-user

### 3. Permission Set Management (17 commands)
- create-ps
- update-ps
- delete-ps
- describe-ps
- put-ps-inline-policy
- delete-ps-inline-policy
- get-ps-inline-policy
- attach-ps-managed-policies
- detach-ps-managed-policies
- list-ps-managed-policies
- attach-ps-customer-managed-policies
- detach-ps-customer-managed-policies
- list-ps-customer-managed-policies
- tag-ps
- untag-ps
- list-ps-tags
- provision-ps

### 4. Account Assignment Management (2 commands)
- create-account-assignment
- delete-account-assignment

### 5. Assignment Viewing (12 commands)
- list-assigned-principals-for-ps-in-account
- list-accounts-for-provisioned-ps
- list-all-acct-assignments-for-provisioned-ps
- list-all-acct-assignments-for-user
- list-all-acct-assignments-for-group
- list-all-acct-assignments-for-principal
- list-all-acct-assignments-for-ps-in-org
- list-all-ps-in-org
- list-ps-provisioned-to-account
- list-all-ps-assignments-in-account
- list-all-ps-assignments-in-ou
- verify-access-for-user

### 6. Organizational Structure (3 commands)
- list-all-accounts-in-ou
- list-all-accounts-in-org
- list-accounts

### 7. Account Information (1 command)
- describe-account

### 8. Application Management (11 commands)
- list-ttis
- describe-tti
- list-applications
- describe-application
- list-application-assignments
- list-application-providers
- list-application-access-scopes
- list-application-auth-methods
- list-application-grants
- create-app-assignment
- delete-app-assignment

## COMMANDS BY CATEGORY

### 1. RESOURCE LOOKUP COMMANDS

These commands convert between resource identifiers (names ↔ IDs ↔ ARNs) and are used both interactively and internally by other commands.

#### Account Lookup

**lookup-account-name** **--account-id** *ACCOUNT_ID*
: Look up account name from account ID
```
aws-sso-admin lookup-account-name --account-id 123456789012
```

**lookup-account-id** **--account-name** *ACCOUNT_NAME*
: Look up account ID from account name
```
aws-sso-admin lookup-account-id --account-name "Production"
```

#### Organizational Unit Lookup

**lookup-ou-name** [**--ou-id** *OU_ID* | **--ou-arn** *OU_ARN*]
: Look up OU name from OU ID or ARN
```
aws-sso-admin lookup-ou-name --ou-id ou-abcd-12345678
aws-sso-admin lookup-ou-name --ou-arn arn:aws:organizations::...
```

**lookup-ou-id** **--ou-name** *OU_NAME*
: Look up OU ID from OU name
```
aws-sso-admin lookup-ou-id --ou-name "Production"
```

**lookup-ou-arn** [**--ou-name** *OU_NAME* | **--ou-id** *OU_ID*]
: Look up OU ARN from OU name or ID
```
aws-sso-admin lookup-ou-arn --ou-name "Production"
aws-sso-admin lookup-ou-arn --ou-id ou-abcd-12345678
```

#### User Lookup

**lookup-user-name** **--user-id** *USER_ID*
: Look up user name (email) from user ID
```
aws-sso-admin lookup-user-name --user-id 9068c0a0-a0d1-70e5-6e7b-90670fb228f5
```

**lookup-user-id** **--user-name** *USER_NAME*
: Look up user ID from user name (email)
```
aws-sso-admin lookup-user-id --user-name user@example.com
```

#### Group Lookup

**lookup-group-name** **--group-id** *GROUP_ID*
: Look up group name from group ID
```
aws-sso-admin lookup-group-name --group-id 9068f010-70e1-7019-0ba9-f049ab9eafad
```

**lookup-group-id** **--group-name** *GROUP_NAME*
: Look up group ID from group name
```
aws-sso-admin lookup-group-id --group-name "Developers"
```

#### Permission Set Lookup

**lookup-ps-name** **--ps-arn** *PS_ARN*
: Look up permission set name from ARN
```
aws-sso-admin lookup-ps-name --ps-arn arn:aws:sso:::permissionSet/...
```

**lookup-ps-arn** **--ps-name** *PS_NAME*
: Look up permission set ARN from name
```
aws-sso-admin lookup-ps-arn --ps-name "AdministratorAccess"
```

#### Application Lookup

**lookup-app-name** **--app-arn** *APP_ARN*
: Look up application name from ARN
```
aws-sso-admin lookup-app-name --app-arn arn:aws:sso::...
```

**lookup-app-arn** **--app-name** *APP_NAME*
: Look up application ARN from name
```
aws-sso-admin lookup-app-arn --app-name "MyApplication"
```

#### Trusted Token Issuer Lookup

**lookup-tti-name** **--tti-arn** *TTI_ARN*
: Look up TTI name from ARN
```
aws-sso-admin lookup-tti-name --tti-arn arn:aws:sso::...
```

**lookup-tti-arn** **--tti-name** *TTI_NAME*
: Look up TTI ARN from name
```
aws-sso-admin lookup-tti-arn --tti-name "MyTTI"
```

---

### 2. USER AND GROUP MANAGEMENT COMMANDS

These commands manage Identity Center users, groups, and group memberships.

**WARNING**: When Identity Center is integrated with an external IdP (e.g., Microsoft Entra),  commands that perform write operations on users and groups may result in conflicts or inconsistencies with users and groups synced from the external IdP. See NOTES below for details. Read operations are always safe.

#### Group Operations

**create-group** **--group-name** *GROUP_NAME* [**--group-desc** *DESCRIPTION*]
: Create a new group
```
aws-sso-admin create-group --group-name "Developers" --group-desc "Development team"
```

**delete-group** [**--group-name** *GROUP_NAME* | **--group-id** *GROUP_ID*]
: Delete a group
```
aws-sso-admin delete-group --group-name "Developers"
aws-sso-admin delete-group --group-id 9068f010-70e1-7019-0ba9-f049ab9eafad
```

**describe-group** [**--group-name** *GROUP_NAME* | **--group-id** *GROUP_ID*]
: Display detailed information about a group
```
aws-sso-admin describe-group --group-name "Developers"
```

**list-groups**
: List all groups in Identity Center
```
aws-sso-admin list-groups
aws-sso-admin list-groups -j
```

#### User Operations

**describe-user** [**--user-name** *USER_NAME* | **--user-id** *USER_ID*]
: Display detailed information about a user
```
aws-sso-admin describe-user --user-name user@example.com
aws-sso-admin describe-user --user-id 9068c0a0-a0d1-70e5-6e7b-90670fb228f5
```

**create-users** **--users** *JSON_FILE*
: Create multiple users from JSON file
```
aws-sso-admin create-users --users file:///path/to/users.json
```

JSON format:
```json
[
  {
    "UserName": "user1@example.com",
    "GivenName": "John",
    "FamilyName": "Doe",
    "DisplayName": "John Doe"
  }
]
```

**delete-users** **--users** *USER_LIST*
: Delete multiple users (comma-separated emails or user IDs)
```
aws-sso-admin delete-users --users "user1@example.com,user2@example.com"
```

**get-users** **--users** *USER_LIST*
: Get details for multiple users (comma-separated emails or user IDs)
```
aws-sso-admin get-users --users "user1@example.com,user2@example.com"
```

**list-users**
: List all users in Identity Center
```
aws-sso-admin list-users
aws-sso-admin list-users -j
```

#### Group Membership Operations

**create-group-membership** **--group-name** *GROUP_NAME* **--user-name** *USER_NAME*
: Add a user to a group
```
aws-sso-admin create-group-membership --group-name "Developers" --user-name user@example.com
```

**create-group-memberships** **--group-name** *GROUP_NAME* **--users** *USER_LIST*
: Add multiple users to a group (comma-separated emails)
```
aws-sso-admin create-group-memberships --group-name "Developers" --users "user1@example.com,user2@example.com"
```

**get-group-membership** **--group-name** *GROUP_NAME* **--user-name** *USER_NAME*
: Check if a user is a member of a group
```
aws-sso-admin get-group-membership --group-name "Developers" --user-name user@example.com
```

**get-group-memberships** **--group-name** *GROUP_NAME* **--users** *USER_LIST*
: Check membership for multiple users in a group
```
aws-sso-admin get-group-memberships --group-name "Developers" --users "user1@example.com,user2@example.com"
```

**delete-group-membership** **--group-name** *GROUP_NAME* **--user-name** *USER_NAME*
: Remove a user from a group
```
aws-sso-admin delete-group-membership --group-name "Developers" --user-name user@example.com
```

**delete-group-memberships** **--group-name** *GROUP_NAME* **--users** *USER_LIST*
: Remove multiple users from a group
```
aws-sso-admin delete-group-memberships --group-name "Developers" --users "user1@example.com,user2@example.com"
```

**list-group-memberships** **--group-name** *GROUP_NAME*
: List all members of a group
```
aws-sso-admin list-group-memberships --group-name "Developers"
```

**list-all-group-memberships-for-user** **--user-name** *USER_NAME*
: List all groups a user belongs to
```
aws-sso-admin list-all-group-memberships-for-user --user-name user@example.com
```

---

### 3. PERMISSION SET MANAGEMENT COMMANDS

These commands manage the full lifecycle of permission sets including CRUD operations, policy attachments, tagging, and provisioning.

#### Permission Set CRUD

**create-ps** **--ps-name** *PS_NAME* [**--ps-desc** *DESCRIPTION*] [**--session-duration** *DURATION*] [**--relay-state** *URL*] [**--tags** *TAGS*]
: Create a new permission set
```
aws-sso-admin create-ps --ps-name "DeveloperAccess" --ps-desc "Developer access" --session-duration PT8H
aws-sso-admin create-ps --ps-name "DeveloperAccess" --tags "Env=Dev,Team=Engineering"
```

**update-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--ps-desc** *DESCRIPTION*] [**--session-duration** *DURATION*] [**--relay-state** *URL*]
: Update an existing permission set
```
aws-sso-admin update-ps --ps-name "DeveloperAccess" --session-duration PT12H
```

**delete-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: Delete a permission set
```
aws-sso-admin delete-ps --ps-name "DeveloperAccess"
```

**describe-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: Display detailed information about a permission set
```
aws-sso-admin describe-ps --ps-name "DeveloperAccess"
aws-sso-admin describe-ps --ps-arn arn:aws:sso:::permissionSet/...
```

#### Inline Policy Management

**put-ps-inline-policy** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--policy** *POLICY*
: Attach an inline policy to a permission set
```
aws-sso-admin put-ps-inline-policy --ps-name "DeveloperAccess" --policy file:///path/to/policy.json
aws-sso-admin put-ps-inline-policy --ps-name "DeveloperAccess" --policy '{"Version":"2012-10-17",...}'
```

**delete-ps-inline-policy** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: Remove the inline policy from a permission set
```
aws-sso-admin delete-ps-inline-policy --ps-name "DeveloperAccess"
```

**get-ps-inline-policy** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: Retrieve the inline policy for a permission set
```
aws-sso-admin get-ps-inline-policy --ps-name "DeveloperAccess"
```

#### AWS Managed Policy Management

**attach-ps-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--policies** *POLICY_ARNS*
: Attach AWS managed policies to a permission set
```
aws-sso-admin attach-ps-managed-policies --ps-name "DeveloperAccess" --policies "arn:aws:iam::aws:policy/PowerUserAccess"
aws-sso-admin attach-ps-managed-policies --ps-name "DeveloperAccess" --policies "arn:aws:iam::aws:policy/ReadOnlyAccess,arn:aws:iam::aws:policy/PowerUserAccess"
```

**detach-ps-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--policies** *POLICY_ARNS*
: Detach AWS managed policies from a permission set
```
aws-sso-admin detach-ps-managed-policies --ps-name "DeveloperAccess" --policies "arn:aws:iam::aws:policy/PowerUserAccess"
```

**list-ps-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: List AWS managed policies attached to a permission set
```
aws-sso-admin list-ps-managed-policies --ps-name "DeveloperAccess"
```

#### Customer Managed Policy Management

**attach-ps-customer-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--policies** *POLICY_NAMES* **--policy-path** *PATH*
: Attach customer managed policies to a permission set
```
aws-sso-admin attach-ps-customer-managed-policies --ps-name "DeveloperAccess" --policies "MyCustomPolicy" --policy-path "/"
```

**detach-ps-customer-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--policies** *POLICY_NAMES* **--policy-path** *PATH*
: Detach customer managed policies from a permission set
```
aws-sso-admin detach-ps-customer-managed-policies --ps-name "DeveloperAccess" --policies "MyCustomPolicy" --policy-path "/"
```

**list-ps-customer-managed-policies** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: List customer managed policies attached to a permission set
```
aws-sso-admin list-ps-customer-managed-policies --ps-name "DeveloperAccess"
```

#### Tagging Operations

**tag-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--tags** *TAGS*
: Add tags to a permission set
```
aws-sso-admin tag-ps --ps-name "DeveloperAccess" --tags "Env=Dev,Team=Engineering"
aws-sso-admin tag-ps --ps-name "DeveloperAccess" --tags '[{"Key":"Env","Value":"Dev"}]'
```

**untag-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] **--tag-keys** *TAG_KEYS*
: Remove tags from a permission set
```
aws-sso-admin untag-ps --ps-name "DeveloperAccess" --tag-keys "Env,Team"
```

**list-ps-tags** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: List tags for a permission set
```
aws-sso-admin list-ps-tags --ps-name "DeveloperAccess"
```

#### Provisioning

**provision-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--target-type** *TYPE*] [**--target-id** *TARGET_ID*]
: Provision a permission set to accounts

Provision to all accounts with existing assignments:
```
aws-sso-admin provision-ps --ps-name "DeveloperAccess" --target-type ALL_PROVISIONED_ACCOUNTS
```

Provision to a specific account:
```
aws-sso-admin provision-ps --ps-name "DeveloperAccess" --target-type AWS_ACCOUNT --target-id 123456789012
```

**Note**: Provisioning to ALL_PROVISIONED_ACCOUNTS only updates accounts that already have assignments for the permission set. Use create-account-assignment first to establish new assignments.

---

### 4. ACCOUNT ASSIGNMENT MANAGEMENT COMMANDS

These commands create and remove assignments of permission sets to principals (users or groups) in AWS accounts.

**create-account-assignment** **--account-id** *ACCOUNT_ID* [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--user-name** *USER* | **--user-id** *USER_ID* | **--group-name** *GROUP* | **--group-id** *GROUP_ID*]
: Create an account assignment

Assign by names:
```
aws-sso-admin create-account-assignment --account-id 123456789012 --ps-name "DeveloperAccess" --user-name user@example.com
aws-sso-admin create-account-assignment --account-id 123456789012 --ps-name "DeveloperAccess" --group-name "Developers"
```

Assign by IDs:
```
aws-sso-admin create-account-assignment --account-id 123456789012 --ps-arn arn:aws:sso:::permissionSet/... --user-id 9068c0a0-...
```

**delete-account-assignment** **--account-id** *ACCOUNT_ID* [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--user-name** *USER* | **--user-id** *USER_ID* | **--group-name** *GROUP* | **--group-id** *GROUP_ID*]
: Delete an account assignment
```
aws-sso-admin delete-account-assignment --account-id 123456789012 --ps-name "DeveloperAccess" --user-name user@example.com
aws-sso-admin delete-account-assignment --account-id 123456789012 --ps-name "DeveloperAccess" --group-name "Developers"
```

---

### 5. ASSIGNMENT VIEWING COMMANDS

These commands provide different perspectives on account assignments across the organization.

#### Permission Set-Centric Views

**list-assigned-principals-for-ps-in-account** **--account-id** *ACCOUNT_ID* [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--show-principal-names** | **--no-show-principal-names**]
: Show all users and groups with a permission set in a specific account
```
aws-sso-admin list-assigned-principals-for-ps-in-account --account-id 123456789012 --ps-name "DeveloperAccess"
aws-sso-admin list-assigned-principals-for-ps-in-account --account-id 123456789012 --ps-name "DeveloperAccess" --show-principal-names
```

**list-accounts-for-provisioned-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--show-acct-names** | **--no-show-acct-names**]
: Show all accounts where a permission set is provisioned
```
aws-sso-admin list-accounts-for-provisioned-ps --ps-name "DeveloperAccess"
aws-sso-admin list-accounts-for-provisioned-ps --ps-name "DeveloperAccess" --show-acct-names
```

**list-all-acct-assignments-for-provisioned-ps** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--show-acct-names**] [**--show-principal-names**] [**--show-target-arns**]
: Show all assignments for a permission set across all accounts
```
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "DeveloperAccess"
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "DeveloperAccess" --show-acct-names --show-principal-names
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "DeveloperAccess" --show-target-arns
```

**list-all-acct-assignments-for-ps-in-org** [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*] [**--show-acct-names**]
: Organization-wide view of assignments for a permission set
```
aws-sso-admin list-all-acct-assignments-for-ps-in-org --ps-name "DeveloperAccess"
```

**list-all-ps-in-org** [**--show-ps-desc**]
: List all permission sets in the organization
```
aws-sso-admin list-all-ps-in-org
aws-sso-admin list-all-ps-in-org --show-ps-desc
```

#### Principal-Centric Views

**list-all-acct-assignments-for-user** [**--user-name** *USER_NAME* | **--user-id** *USER_ID*] [**--show-acct-names**] [**--show-ps-desc**] [**--show-target-arns**]
: Show all account assignments for a specific user
```
aws-sso-admin list-all-acct-assignments-for-user --user-name user@example.com
aws-sso-admin list-all-acct-assignments-for-user --user-name user@example.com --show-acct-names --show-ps-desc
aws-sso-admin list-all-acct-assignments-for-user --user-name user@example.com --show-target-arns
```

**list-all-acct-assignments-for-group** [**--group-name** *GROUP_NAME* | **--group-id** *GROUP_ID*] [**--show-acct-names**] [**--show-ps-desc**] [**--show-target-arns**]
: Show all account assignments for a specific group
```
aws-sso-admin list-all-acct-assignments-for-group --group-name "Developers"
aws-sso-admin list-all-acct-assignments-for-group --group-name "Developers" --show-acct-names --show-ps-desc
```

**list-all-acct-assignments-for-principal** [**--user-name** *USER* | **--user-id** *USER_ID* | **--group-name** *GROUP* | **--group-id** *GROUP_ID*] [**--show-acct-names**] [**--show-ps-desc**] [**--show-target-arns**]
: Show all assignments for a user or group (flexible principal specification)
```
aws-sso-admin list-all-acct-assignments-for-principal --user-name user@example.com
aws-sso-admin list-all-acct-assignments-for-principal --group-name "Developers"
```

**verify-access-for-user** [**--user-name** *USER_NAME* | **--user-id** *USER_ID*] **--account-id** *ACCOUNT_ID* [**--ps-name** *PS_NAME* | **--ps-arn** *PS_ARN*]
: Verify if a user has specific access to an account
```
aws-sso-admin verify-access-for-user --user-name user@example.com --account-id 123456789012 --ps-name "DeveloperAccess"
```

#### Account-Centric Views

**list-ps-provisioned-to-account** **--account-id** *ACCOUNT_ID* [**--show-ps-desc**]
: Show all permission sets provisioned to a specific account
```
aws-sso-admin list-ps-provisioned-to-account --account-id 123456789012
aws-sso-admin list-ps-provisioned-to-account --account-id 123456789012 --show-ps-desc
```

**list-all-ps-assignments-in-account** **--account-id** *ACCOUNT_ID* [**--show-principal-names**] [**--show-ps-desc**]
: Show all permission set assignments in a specific account
```
aws-sso-admin list-all-ps-assignments-in-account --account-id 123456789012
aws-sso-admin list-all-ps-assignments-in-account --account-id 123456789012 --show-principal-names --show-ps-desc
```

**list-all-ps-assignments-in-ou** [**--ou-name** *OU_NAME* | **--ou-id** *OU_ID*] [**--show-acct-names**] [**--show-principal-names**] [**--show-ps-desc**]
: Show all permission set assignments in an organizational unit (recursive)
```
aws-sso-admin list-all-ps-assignments-in-ou --ou-name "Production"
aws-sso-admin list-all-ps-assignments-in-ou --ou-name "Production" --show-acct-names --show-principal-names
```

---

### 6. ORGANIZATIONAL STRUCTURE COMMANDS

These commands display AWS Organizations structure in hierarchical tree format.

**list-all-accounts-in-ou** [**--ou-name** *OU_NAME* | **--ou-id** *OU_ID*] [**--full-tree**] [**--ou-tree**] [**--stats**] [**--ascii**]
: Display accounts and OUs in hierarchical tree format

Show full tree with all accounts:
```
aws-sso-admin list-all-accounts-in-ou --ou-name "Production" --full-tree
```

Show only OU structure (suppress accounts):
```
aws-sso-admin list-all-accounts-in-ou --ou-name "Production" --ou-tree
```

Show statistics only:
```
aws-sso-admin list-all-accounts-in-ou --ou-name "Production" --stats
```

Use ASCII characters for compatibility:
```
aws-sso-admin list-all-accounts-in-ou --ou-name "Production" --full-tree --ascii
```

**list-all-accounts-in-org** [**--full-tree**] [**--ou-tree**] [**--stats**] [**--ascii**]
: Alias for list-all-accounts-in-ou with root OU (organization-wide view)
```
aws-sso-admin list-all-accounts-in-org --full-tree
aws-sso-admin list-all-accounts-in-org --ou-tree
```

**list-accounts**
: Flat list of all accounts with parent OU information
```
aws-sso-admin list-accounts
aws-sso-admin list-accounts -j
```

---

### 7. ACCOUNT INFORMATION COMMANDS

**describe-account** [**--account-name** *ACCOUNT_NAME* | **--account-id** *ACCOUNT_ID*]
: Display detailed account information including metadata, parent OU, and tags
```
aws-sso-admin describe-account --account-name "Production"
aws-sso-admin describe-account --account-id 123456789012
aws-sso-admin describe-account --account-id 123456789012 -j
```

Output includes:
- Account ID, name, email, status
- Parent OU information
- Account join date and method
- Account tags (if any)

---

### 8. APPLICATION MANAGEMENT COMMANDS

These commands manage IAM Identity Center applications and trusted token issuers (TTI).

#### Trusted Token Issuer Operations

**list-ttis**
: List all trusted token issuers with full details

Output is always JSON format containing detailed TTI configurations:
```
aws-sso-admin list-ttis
```

**describe-tti** **--tti-name** *TTI_NAME*
: Show detailed information about a specific trusted token issuer

Output is always JSON format:
```
aws-sso-admin describe-tti --tti-name "MyTTI"
```

#### Application Operations

**list-applications**
: List all applications

Output is always JSON format:
```
aws-sso-admin list-applications
```

**describe-application** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*]
: Show detailed information about a specific application

Output is always JSON format:
```
aws-sso-admin describe-application --app-name "MyApplication"
aws-sso-admin describe-application --app-arn arn:aws:sso::...
```

**list-application-assignments** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*]
: List all assignments for an application (shows which users/groups have access)
```
aws-sso-admin list-application-assignments --app-name "MyApplication"
```

**list-application-providers**
: List all available application providers

Output is always JSON format containing full provider metadata:
```
aws-sso-admin list-application-providers
```

**list-application-access-scopes** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*]
: List OAuth/OIDC access scopes for an application
```
aws-sso-admin list-application-access-scopes --app-name "MyApplication"
```

**list-application-auth-methods** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*]
: List authentication methods configured for an application

Output is always JSON format:
```
aws-sso-admin list-application-auth-methods --app-name "MyApplication"
```

**list-application-grants** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*]
: List OAuth/OIDC grants for an application

Output is always JSON format:
```
aws-sso-admin list-application-grants --app-name "MyApplication"
```

#### Application Assignment Operations

**create-app-assignment** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*] [**--user-name** *USER* | **--user-id** *USER_ID* | **--group-name** *GROUP* | **--group-id** *GROUP_ID*]
: Assign an application to a user or group
```
aws-sso-admin create-app-assignment --app-name "MyApplication" --user-name user@example.com
aws-sso-admin create-app-assignment --app-name "MyApplication" --group-name "Developers"
```

**delete-app-assignment** [**--app-name** *APP_NAME* | **--app-arn** *APP_ARN*] [**--user-name** *USER* | **--user-id** *USER_ID* | **--group-name** *GROUP* | **--group-id** *GROUP_ID*]
: Remove an application assignment
```
aws-sso-admin delete-app-assignment --app-name "MyApplication" --user-name user@example.com
aws-sso-admin delete-app-assignment --app-name "MyApplication" --group-name "Developers"
```

---

## OUTPUT FORMATS

Most commands support two output formats controlled by the **-j** or **--json-only** flag:

**Human-Readable Output (Default)**
: Formatted output optimized for readability with hierarchical displays, bullet points, tree structures, and descriptive labels.

**JSON Output**
: Machine-readable JSON format suitable for parsing by scripts and tools. Produces valid JSON with arrays for lists and consistent structure across commands.

Example:
```bash
# Human-readable output
aws-sso-admin list-groups

# JSON output
aws-sso-admin list-groups -j | jq '.[] | select(.DisplayName | startswith("Dev"))'
```

---

## OUTPUT CUSTOMIZATION FLAGS

Many viewing commands support output customization flags to control detail level and API call optimization:

**--show-acct-names** / **--no-show-acct-names**
: Show or hide AWS account names (reduces API calls when hidden)

**--show-principal-names** / **--no-show-principal-names**
: Show or hide user/group names (reduces API calls when hidden)

**--show-ps-desc** / **--no-show-ps-desc**
: Show or hide permission set descriptions (reduces API calls when hidden)

**--show-target-arns** / **--no-show-target-arns**
: Show or hide assume-role target ARNs extracted from PS inline policies (expensive operation)

**--qa**
: Suppress AdministratorAccess entries from output

**--ascii**
: Use ASCII-only characters for tree displays (for terminal compatibility)

**--compact** / **--no-compact**
: Toggle compact vs expanded output format

**--full-tree**
: Show complete recursive organizational tree with all accounts

**--ou-tree**
: Show only OU structure, suppress account details

**--stats**
: Show only statistics summary

### Performance Optimization

Using **--no-\*** flags not only hides output but also **skips the corresponding API calls entirely**, reducing:
- Execution time for large operations
- API call volume
- AWS service throttling risk

Example:
```bash
# Fast - skips account name lookups
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "DeveloperAccess" --no-show-acct-names

# Detailed - includes account names (more API calls)
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "DeveloperAccess" --show-acct-names
```

---

## ASSUME-ROLE TARGET ARNS FEATURE

The **--show-target-arns** flag extracts target IAM roles from "glue" permission sets.

### Use Case

Identity Center does not natively support direct SSO access to conventional IAM roles. To work around this, administrators create "glue" permission sets with inline policies that allow **sts:AssumeRole** to specific conventional IAM roles, allowing end users to assume these roles via SSO sign-in.

The **--show-target-arns** flag reveals which conventional roles users can actually access through these glue permission sets, making it easier to understand the real access granted by Identity Center assignments.

### Output Format

```
- Assume-role targets for this PS:
  * arn:aws:iam::123456789012:role/ConventionalRole1
  * arn:aws:iam::123456789012:role/ConventionalRole2
```

### Applicable Commands

Available on assignment viewing commands:
- list-all-acct-assignments-for-provisioned-ps
- list-all-acct-assignments-for-user
- list-all-acct-assignments-for-group
- list-all-acct-assignments-for-principal
- list-all-ps-assignments-in-account

---

## EXIT STATUS

**0**
: Success

**1**
: Error (AWS API error, resource not found, invalid arguments, etc.)

**130**
: Keyboard interrupt (Ctrl+C)

---

## EXAMPLES

### Common Workflow: Grant User Access to an Account

```bash
# 1. Look up the user
aws-sso-admin describe-user --user-name user@example.com

# 2. Look up the account
aws-sso-admin describe-account --account-name "Production"

# 3. Look up or create a permission set
aws-sso-admin describe-ps --ps-name "DeveloperAccess" || \
  aws-sso-admin create-ps --ps-name "DeveloperAccess" --ps-desc "Developer access"

# 4. Create the assignment
aws-sso-admin create-account-assignment \
  --account-id 123456789012 \
  --ps-name "DeveloperAccess" \
  --user-name user@example.com

# 5. Verify the assignment
aws-sso-admin verify-access-for-user \
  --user-name user@example.com \
  --account-id 123456789012 \
  --ps-name "DeveloperAccess"
```

### Common Workflow: Audit User Access

```bash
# Show all access for a user
aws-sso-admin list-all-acct-assignments-for-user \
  --user-name user@example.com \
  --show-acct-names \
  --show-ps-desc

# Show all groups the user belongs to
aws-sso-admin list-all-group-memberships-for-user --user-name user@example.com

# Check group access
aws-sso-admin list-all-acct-assignments-for-group \
  --group-name "Developers" \
  --show-acct-names
```

### Common Workflow: Review Permission Set Usage

```bash
# List all permission sets
aws-sso-admin list-all-ps-in-org --show-ps-desc

# Show where a permission set is assigned
aws-sso-admin list-all-acct-assignments-for-provisioned-ps \
  --ps-name "DeveloperAccess" \
  --show-acct-names \
  --show-principal-names

# Show all accounts with the permission set
aws-sso-admin list-accounts-for-provisioned-ps \
  --ps-name "DeveloperAccess" \
  --show-acct-names
```

### Common Workflow: Organizational Structure Review

```bash
# Show full organizational tree
aws-sso-admin list-all-accounts-in-org --full-tree

# Show only OU structure
aws-sso-admin list-all-accounts-in-org --ou-tree

# Show statistics
aws-sso-admin list-all-accounts-in-org --stats

# Show assignments in an OU
aws-sso-admin list-all-ps-assignments-in-ou \
  --ou-name "Production" \
  --show-acct-names \
  --show-principal-names
```

---

## FILES

**~/.aws/credentials**
: AWS credentials file

**~/.aws/config**
: AWS configuration file

---

## NOTES

### External IdP Integration (CAUTION)

Note that commands that create or perform write operations on users and groups may result in conflicts or inconsistencies with users and groups synced from an external IdP, in the case when Identity Center is integrated with an external identity provider (e.g., Microsoft Entra).  Be careful not to operate on external users and groups unintentionally.  As a safeguard you may disallow these actions via administrative policy or SCP.

### Permission Set Provisioning

Creating an account assignment automatically provisions the permission set to that account. However, changes to the permission set (policy updates, etc.) require explicit re-provisioning using the **provision-ps** command.

### API Rate Limiting

Be aware of AWS API rate limits when running commands on large organizations:
- Use **--no-show-\*** flags to reduce API calls
- Spread large operations over time
- Consider AWS service quotas and throttling

---

## SEE ALSO

AWS IAM Identity Center Documentation: https://docs.aws.amazon.com/singlesignon/

AWS CLI SSO Admin Reference: https://docs.aws.amazon.com/cli/latest/reference/sso-admin/

---

## AUTHOR

Written for AWS Identity Center administration and automation.

## COPYRIGHT

See LICENSE file for copyright and licensing information.

---

**AWS-SSO-ADMIN** | Version 1.0 | AWS IAM Identity Center Tools
