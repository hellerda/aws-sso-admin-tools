# Overview

This project is a set of tools to help you perform administration of AWS Identity Center.  With it you can manage the following resources:

- Users and groups
- Permission sets
- Account assignments
- Registered OIDC or SAML applications

The program supports most operations you can do via the AWS management console or AWS CLI.  But the program has several advantages:

- Operations that require several commands in AWS CLI can be done in single command.
- The AWS CLI commands generally require user and group ids or permission set or application Arns as input.  The program accepts input and displays output using the "friendly names" for these objects, so you don't have to lookup the ids or Arns.
- The program provides many views that are not available or difficult to generate through the AWS Console or AWS CLI, like the ability to list account assignments by user, group, permission set, account or org, and the ability to print a full Org or OU tree.


## Build and install

[pipx](https://pipx.pypa.io/) install is recommended, as it will automatically handle dependencies:

```bash
# Install pipx if you don't have it
python -m pip install --user pipx
python -m pipx ensurepath

# Build and install aws-sso-admin with pipx
cd <project directory>
pipx run build
pipx install ./dist/aws_sso_admin_tools-n.n.n-py3-none-any.whl
```

## Running the program

To see the list of available commands:
```bash
$ aws-sso-admin help
```
Most commands require options.  To see the supported options, refer to the examples or run:
```bash
$ aws-sso-admin <command> --help
```


# Examples

The following examples demonstrate common usage patterns organized by functional category. For complete command reference including all options and detailed descriptions, see [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md).

## 1. Resource Lookup Commands

These commands convert between resource identifiers (names ↔ IDs ↔ ARNs):

```bash
# User lookups
aws-sso-admin lookup-user-id --user-name "ima.user@my.org"
aws-sso-admin lookup-user-name --user-id "11111111-1111-1111-1111-111111111111"

# Group lookups
aws-sso-admin lookup-group-id --group-name "App1_Deployers"
aws-sso-admin lookup-group-name --group-id "22222222-2222-2222-2222-222222222222"

# Permission set lookups
aws-sso-admin lookup-ps-arn --ps-name "AdministratorAccess"
aws-sso-admin lookup-ps-name --ps-arn "arn:aws:sso:::permissionSet/ssoins-abcdef1234567890/ps-1234567890123456"

# Application lookups
aws-sso-admin lookup-app-arn --app-name "My-Custom-App"
aws-sso-admin lookup-app-name --app-arn "arn:aws:sso::123456789012:application/ssoins-abcdef1234567890/apl-a1b2c3d4e5f67890"

# Account lookups
aws-sso-admin lookup-account-id --acct-name "my-sandbox-account"
aws-sso-admin lookup-account-name --acct-id 123456789012

# OU lookups
aws-sso-admin lookup-ou-id --ou-name "Root"
aws-sso-admin lookup-ou-id --ou-name "MyChildOU"
aws-sso-admin lookup-ou-name --ou-id "o-abcde12345"
aws-sso-admin lookup-ou-name --ou-id "ou-w0yz-abcd1234"
```

## 2. User and Group Management Commands

**WARNING**: Any operation that modifies a User or Group resource can result in inconsistencies or conflicts when your Identity Center uses an external IdP like MS Entra. If this is not intended you should disallow these operations in IAM policy. All the read-only operations are safe, though.

### Group operations
```bash
aws-sso-admin create-group --group-name "App1_Deployers" --group-desc "Can deploy the sample app"
aws-sso-admin describe-group --group-name "App1_Deployers"
aws-sso-admin list-groups
aws-sso-admin delete-group --group-name "App1_Deployers"
```

### User operations
```bash
aws-sso-admin list-users
aws-sso-admin describe-user --user-name "ima.user@my.org"
```

### Group membership operations

Commands ending with `-users` (plural) or `-memberships` (plural) operate on multiple users and require a `--user-file` parameter pointing to a JSON file. The file should contain a list of user objects with `FamilyName`, `GivenName`, and `Email` fields.

Commands ending with `-user` or `-membership` (singular) operate on a single user specified by `--user-name` or `--user-id`.

```bash
# Bulk operations (multiple users from JSON file):
aws-sso-admin create-users --user-file users.json
aws-sso-admin get-users --user-file users.json
aws-sso-admin delete-users --user-file users.json
aws-sso-admin create-group-memberships --group-name "App1_Deployers" --user-file users.json
aws-sso-admin get-group-memberships --group-name "App1_Deployers" --user-file users.json
aws-sso-admin delete-group-memberships --group-name "App1_Deployers" --user-file users.json

# Single user operations:
aws-sso-admin create-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
aws-sso-admin get-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
aws-sso-admin delete-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"

# List group members and user's groups
aws-sso-admin list-group-memberships --group-name "App1_Deployers"
aws-sso-admin list-all-group-memberships-for-user --user-name "ima.user@my.org"
```

## 3. Permission Set Management Commands

### Basic permission set operations
```bash
aws-sso-admin create-ps --ps-name "App1_Deployer"
aws-sso-admin create-ps --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H
aws-sso-admin update-ps --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H
aws-sso-admin describe-ps --ps-name "App1_Deployer"
aws-sso-admin delete-ps --ps-name "App1_Deployer"
```

### Policy management
```bash
# Inline policies
aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer" --policy file:///tmp/policy.json
aws-sso-admin get-ps-inline-policy --ps-name "App1_Deployer" | jq -r .InlinePolicy | jq
aws-sso-admin delete-ps-inline-policy --ps-name "App1_Deployer"

# AWS managed policies
aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" --policy-arns "arn:aws:iam::aws:policy/PowerUserAccess"
aws-sso-admin list-ps-managed-policies --ps-name "App1_Deployer"
aws-sso-admin detach-ps-managed-policies --ps-name "App1_Deployer" --policy-arns "arn:aws:iam::aws:policy/PowerUserAccess"

# Customer managed policies
aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" --cm-policies "MyPolicy=/"
aws-sso-admin list-ps-customer-managed-policies --ps-name "App1_Deployer"
aws-sso-admin detach-ps-customer-managed-policies --ps-name "App1_Deployer" --cm-policies "MyPolicy=/"
```

### Tagging
```bash
aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags "Environment=Development,Application=Sample"
aws-sso-admin list-ps-tags --ps-name "App1_Deployer"
aws-sso-admin untag-ps --ps-name "App1_Deployer" --tag-keys "Environment,Application"
```

### Provisioning
```bash
# Provision to all assigned accounts
aws-sso-admin provision-ps --ps-name "App1_Deployer"

# Provision to a specific account
aws-sso-admin provision-ps --ps-name "App1_Deployer" --acct-id 123456789012
```

## 4. Account Assignment Management Commands

```bash
# Create assignments
aws-sso-admin create-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012
aws-sso-admin create-account-assignment --ps-name "App1_Deployer" --user-name "ima.user@my.org" --acct-id 123456789012

# Delete assignments
aws-sso-admin delete-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012
```

## 5. Assignment Viewing Commands

### Permission set-centric views
```bash
aws-sso-admin list-assigned-principals-for-ps-in-account --ps-name "App1_Deployer" --acct-id 123456789012
aws-sso-admin list-accounts-for-provisioned-ps --ps-name "App1_Deployer"
aws-sso-admin list-all-acct-assignments-for-provisioned-ps --ps-name "App1_Deployer"
aws-sso-admin list-all-acct-assignments-for-ps-in-org --ps-name "App1_Deployer"
aws-sso-admin list-all-ps-in-org
```

### Principal-centric views
```bash
aws-sso-admin list-all-acct-assignments-for-user --user-name "ima.user@my.org"
aws-sso-admin list-all-acct-assignments-for-group --group-name "App1_Deployers"
aws-sso-admin list-all-acct-assignments-for-principal --user-name "ima.user@my.org"
aws-sso-admin list-all-acct-assignments-for-principal --group-name "App1_Deployers"
aws-sso-admin verify-access-for-user --user-name "ima.user@my.org" --ps-name "App1_Deployer" --acct-id 123456789012
```

### Account-centric views
```bash
aws-sso-admin list-ps-provisioned-to-account --acct-id 123456789012
aws-sso-admin list-all-ps-assignments-in-account --acct-id 123456789012
aws-sso-admin list-all-ps-assignments-in-ou --ou-name "IT"
aws-sso-admin list-all-ps-assignments-in-ou --ou-name "Sandbox"
```

## 6. Organizational Structure Commands

Display AWS Organizations structure in hierarchical tree format:

```bash
# Full organization tree with all accounts
aws-sso-admin list-all-accounts-in-ou --ou-name "Root" --full-tree

# Specific OU with accounts
aws-sso-admin list-all-accounts-in-ou --ou-name "MyChildOU" --full-tree
aws-sso-admin list-all-accounts-in-ou --ou-id "ou-w0yz-abcd1234" --full-tree

# OU structure only (no accounts)
aws-sso-admin list-all-accounts-in-ou --ou-name "Root" --ou-tree

# ASCII-only output for compatibility
aws-sso-admin list-all-accounts-in-ou --ou-name "Root" --full-tree --ascii

# Flat list of accounts
aws-sso-admin list-accounts
```

## 7. Account Information Commands

```bash
aws-sso-admin describe-account --acct-id 123456789012
aws-sso-admin describe-account --acct-name "my-sandbox-account"
```

## 8. Application Management Commands

```bash
# Trusted Token Issuers
aws-sso-admin list-ttis
aws-sso-admin describe-tti --tti-name "My-TrustedTokenIssuer"

# Applications
aws-sso-admin list-applications
aws-sso-admin describe-application --app-name "My-Custom-App"
aws-sso-admin list-application-assignments --app-name "My-Custom-App"
aws-sso-admin list-application-grants --app-name "My-Custom-App"
aws-sso-admin list-application-access-scopes --app-name "My-Custom-App"
aws-sso-admin list-application-auth-methods --app-name "My-Custom-App"
aws-sso-admin list-application-providers

# Application assignments
aws-sso-admin create-app-assignment --app-name "My-Custom-App" --user-name "ima.user@my.org"
aws-sso-admin create-app-assignment --app-name "My-Custom-App" --group-name "App1_Deployers"
aws-sso-admin delete-app-assignment --app-name "My-Custom-App" --user-name "ima.user@my.org"
```

# Advanced operations


```
aws-sso-admin create-ps --ps-name "App1_Deployer" --tags "Environment=Development,Application=Sample"
aws-sso-admin create-ps --ps-name "App1_Deployer" --tags "Environment"="Development","Application"="Sample"

aws-sso-admin create-ps --ps-name "App1_Deployer" --tags '[{"Key":"Environment","Value":"Development"}],{"Key":"Application","Value":"Sample"}'
aws-sso-admin create-ps --ps-name "App1_Deployer" --tags "[{\"Key\":\"Environment\",\"Value\":\"Development\"}],{\"Key\":\"Application\",\"Value\":\"Sample\"}"

aws-sso-admin create-ps --ps-name "App1_Deployer" --tags file:///tmp/tags.json
aws-sso-admin create-ps --ps-name "App1_Deployer" --tags file://<(cat <<EOF
[
  {
    "Key": "Environment",
    "Value": "Development"
  },
  {
    "Key": "Application",
    "Value": "Sample"
  }
]
EOF
)
```
```
aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags "Environment=Development,Application=Sample"
aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags "Environment"="Development","Application"="Sample"

aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags '[{"Key":"Environment","Value":"Development"},{"Key":"Application","Value":"Sample"}]'
aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags "[{\"Key\":\"Environment\",\"Value\":\"Development\"},{\"Key\":\"Application\",\"Value\":\"Sample\"}]"

aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags file:///tmp/tags.json
aws-sso-admin tag-ps --ps-name "App1_Deployer" --tags file://<(cat <<EOF
[
  {
    "Key": "Environment",
    "Value": "Development"
  },
  {
    "Key": "Application",
    "Value": "Sample"
  }
]
EOF
)
```
```
aws-sso-admin untag-ps --ps-name "App1_Deployer" --tag-keys "Environment,Application"
```
```
aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer" --policy '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "ssm:DescribeParameters", "Resource": "*" } ] }'

aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer" --policy "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"ssm:DescribeParameters\", \"Resource\": \"*\" } ] }"

aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer" --policy file:///tmp/policy.json
aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer" --policy file://<(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    }
  ]
}
EOF
)
```

NOTE: The same syntax is supported for ```attach-ps-managed-policies``` and ```detach-ps-managed-policies```.
```
aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" \
--policy-arns "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"

aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" \
--policy-arns "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess, arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"

aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" \
--policy-arns '["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess","arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"]'

aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" \
--policy-arns "[\"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess\",\"arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess\"]"

aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" --policy-arns file:///tmp/policy_arns.json
aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer" --policy-arns file://<(cat <<EOF
[
  "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
  "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
]
EOF
)
```
NOTE: The same syntax is supported for ```attach-ps-customer-managed-policies``` and ```detach-ps-customer-managed-policies```.
```
aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "CustomerPolicy1=/,CustomerPolicy2=/"

aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "CustomerPolicy1"="/","CustomerPolicy2"="/"

aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies '[{"Name":"CustomerPolicy1","Path":"/"},{"Name":"CustomerPolicy2","Path":"/"}]'

aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "[{\"Name\":\"CustomerPolicy1\",\"Path\":\"/\"},{\"Name\":\"CustomerPolicy2\",\"Path\":\"/\"}]"

aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies file:///tmp/cm_policies.json

aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies file://<(cat <<EOF
[
  {
    "Name": "CustomerPolicy1",
    "Path": "/"
  },
  {
    "Name": "CustomerPolicy2",
    "Path": "/"
  }
]
EOF
)
```