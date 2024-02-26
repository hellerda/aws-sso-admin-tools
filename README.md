# Overview

This project is a set of tools to help you manage Users and Groups, and Permission Sets and Account Assignments in AWS Identity Center.  It supports all the operations you can do in AWS management console.  While you can do these operations using AWS CLI as well:
- Some operations that require several commands in AWS CLI can be done in single command in the program.
- The AWS CLI commands generally require user and group ids or PS Arns as input.  The program includes utility functions to do the conversion, so you can specify input and display output using just the "friendly names" for these objects.
- The program supports attach/detach a *list* of managed policies, whereas AWS CLI only accepts one at a time.
- The account-assignment ops provide several views that are not available, or difficult to generate, through AWS Console or CLI.

There are three scripts:
```
manage-account-assignments.py
manage-permission-set.py
manage-users-groups.py
```

Each script supports a set of commands.  To see the supported commands, run the script with ```--help``` or refer to the examples below.

Some commands require input values to be set on the command line.  To see the supported options, run the script with ```--help``` or refer to the examples below.


# Examples

## Simple lookup operations
```
python funcs.py lookup-user-id --user-name "ima.user@my.org"
python funcs.py lookup-group-id --group-name "App1_Deployers"
python funcs.py lookup-ps-arn --ps-name "AdministratorAccess"

python funcs.py lookup-user-name --user-id "11111111-1111-1111-1111-111111111111"
python funcs.py lookup-group-name --group-id "22222222-2222-2222-2222-222222222222"
python funcs.py lookup-ps-name --ps-arn "arn:aws:sso:::permissionSet/ssoins-deadbeefdeadbeef/ps-1234567890123456"
```

## User and Group operations

NOTE: Any operation that modifies a User or Group resource can result in inconsistences or conflicts when your Identity Center uses an external IdP such as Azure AD.  If this is not intended you should disallow these operations in IAM policy.  All the r/o operations are safe, though.

NOTE: For bulk operations, update ```user_list``` in the program (see "Customize this").
```
python manage-users-groups.py create-group --group-name "App1_Deployers" --group-desc "Can deploy the sample app"
python manage-users-groups.py describe-group --group-name "App1_Deployers"
python manage-users-groups.py delete-group --group-name "App1_Deployers"

python manage-users-groups.py list-users
python manage-users-groups.py list-groups
python manage-users-groups.py describe-user --user-name "ima.user@my.org"
python manage-users-groups.py list-group-memberships --group-name "App1_Deployers"
python manage-users-groups.py list-all-group-memberships-for-user --user-name "ima.user@my.org"

# Bulk operations on users:
python manage-users-groups.py create-users
python manage-users-groups.py get-users
python manage-users-groups.py delete-users
python manage-users-groups.py create-group-memberships --group-name "App1_Deployers"
python manage-users-groups.py get-group-memberships --group-name "App1_Deployers"
python manage-users-groups.py delete-group-memberships --group-name "App1_Deployers"

# Operations on individual users:
python manage-users-groups.py create-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
python manage-users-groups.py get-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
python manage-users-groups.py delete-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
```

## Permission Set operations

NOTE: For all ops that accept ```--tags```, ```--policy```, ```--policy-arns``` or ```--cm-policy```: If the option is ommitted, the program looks for the input to be set in the program (see "Customize this").  If no input is set, the program throws an error.
```
python manage-permission-set.py create --ps-name "App1_Deployer"
python manage-permission-set.py create --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H

python manage-permission-set.py update --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H

python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer"
python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer"
python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer"

python manage-permission-set.py describe --ps-name "App1_Deployer"
python manage-permission-set.py get-inline-policy --ps-name "App1_Deployer" | jq -r .InlinePolicy | jq
python manage-permission-set.py list-managed-policies --ps-name "App1_Deployer"
python manage-permission-set.py list-customer-managed-policies --ps-name "App1_Deployer" | jq
python manage-permission-set.py list-tags --ps-name "App1_Deployer"

python manage-permission-set.py delete-inline-policy --ps-name "App1_Deployer"
python manage-permission-set.py detach-managed-policies --ps-name "App1_Deployer"
python manage-permission-set.py detach-customer-managed-policies --ps-name "App1_Deployer"

python manage-permission-set.py delete --ps-name "App1_Deployer"

python manage-permission-set.py provision --ps-name "App1_Deployer"
python manage-permission-set.py provision --ps-name "App1_Deployer" --acct-id 123456789012

python manage-permission-set.py describe --ps-name "AdministratorAccess"
python manage-permission-set.py describe --ps-name "ReadOnlyAccess"
python manage-permission-set.py describe --ps-name "App1_Deployer"
```
### All the supported ways to "create" with tags
```
python manage-permission-set.py create --ps-name "App1_Deployer" --tags "Environment=Development,Application=Sample"
python manage-permission-set.py create --ps-name "App1_Deployer" --tags "Environment"="Development","Application"="Sample"

python manage-permission-set.py create --ps-name "App1_Deployer" --tags '[{"Key":"Environment","Value":"Development"}],{"Key":"Application","Value":"Sample"}'
python manage-permission-set.py create --ps-name "App1_Deployer" --tags "[{\"Key\":\"Environment\",\"Value\":\"Development\"}],{\"Key\":\"Application\",\"Value\":\"Sample\"}"

python manage-permission-set.py create --ps-name "App1_Deployer" --tags file:///tmp/tags.json
python manage-permission-set.py create --ps-name "App1_Deployer" --tags file://<(cat <<EOF
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
### All the supported ways to "tag" an existing PS
```
python manage-permission-set.py tag --ps-name "App1_Deployer" --tags "Environment=Development,Application=Sample"
python manage-permission-set.py tag --ps-name "App1_Deployer" --tags "Environment"="Development","Application"="Sample"

python manage-permission-set.py tag --ps-name "App1_Deployer" --tags '[{"Key":"Environment","Value":"Development"},{"Key":"Application","Value":"Sample"}]'
python manage-permission-set.py tag --ps-name "App1_Deployer" --tags "[{\"Key\":\"Environment\",\"Value\":\"Development\"},{\"Key\":\"Application\",\"Value\":\"Sample\"}]"

python manage-permission-set.py tag --ps-name "App1_Deployer" --tags file:///tmp/tags.json
python manage-permission-set.py tag --ps-name "App1_Deployer" --tags file://<(cat <<EOF
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
### All the supported ways to "untag" an existing PS
```
python manage-permission-set.py untag --ps-name "App1_Deployer" --tag-keys "Environment,Application"
```
### All the supported ways to "put-inline-policy"
```
python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer" --policy '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "ssm:DescribeParameters", "Resource": "*" } ] }'

python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer" --policy "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"ssm:DescribeParameters\", \"Resource\": \"*\" } ] }"

python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer" --policy file:///tmp/policy.json
python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer" --policy file://<(cat <<EOF
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
### All the supported ways to "attach/detach-managed-policies"

NOTE: The identical syntax is supported for ```attach-managed-policies``` and ```detach-managed-policies```.
```
python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" \
--policy-arns "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"

python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" \
--policy-arns "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess, arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"

python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" \
--policy-arns '["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess","arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"]'

python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" \
--policy-arns "[\"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess\",\"arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess\"]"

python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" --policy-arns file:///tmp/policy_arns.json
python manage-permission-set.py attach-managed-policies --ps-name "App1_Deployer" --policy-arns file://<(cat <<EOF
[
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
]
EOF
)
```
### All the supported ways to "attach/detach-customer-managed-policies"
NOTE: The identical syntax is supported for ```attach-customer-managed-policies``` and ```detach-customer-managed-policies```.
```
python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "CustomerPolicy1=/,CustomerPolicy2=/"

python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "CustomerPolicy1"="/","CustomerPolicy2"="/"

python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies '[{"Name":"CustomerPolicy1","Path":"/"},{"Name":"CustomerPolicy2","Path":"/"}]'

python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies "[{\"Name\":\"CustomerPolicy1\",\"Path\":\"/\"},{\"Name\":\"CustomerPolicy2\",\"Path\":\"/\"}]"

python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
--cm-policies file:///tmp/cm_policies.json

python manage-permission-set.py attach-customer-managed-policies --ps-name "App1_Deployer" \
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

## Account Assignment operations

```
python manage-account-assignments.py create-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012
python manage-account-assignments.py delete-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012

python manage-account-assignments.py provision-permission-set --ps-name "App1_Deployer"
python manage-account-assignments.py provision-permission-set --ps-name "App1_Deployer" --acct-id 123456789012

python manage-account-assignments.py list-assigned-principals-for-ps-in-account --ps-name "App1_Deployer" --acct-id 123456789012

python manage-account-assignments.py list-accounts-for-provisioned-permission-set --ps-name "App1_Deployer"
python manage-account-assignments.py list-all-acct-assignments-for-provisioned-permission-set --ps-name "App1_Deployer"

python manage-account-assignments.py list-all-permission-sets-in-org
python manage-account-assignments.py list-all-acct-assignments-for-ps-in-org

python manage-account-assignments.py list-all-acct-assignments-for-principal --user-name "ima.user@my.org"
python manage-account-assignments.py list-all-acct-assignments-for-principal --group-name "App1_Deployers"

python manage-account-assignments.py list-all-acct-assignments-for-user --user-name "ima.user@my.org"

python manage-account-assignments.py list-permission-sets-provisioned-to-account --acct-id 123456789012
python manage-account-assignments.py list-all-permission-set-assignments-in-account --acct-id 123456789012

python manage-account-assignments.py list-all-permission-set-assignments-in-ou --ou-name "IT"
python manage-account-assignments.py list-all-permission-set-assignments-in-ou --ou-name "Sandbox"

python manage-account-assignments.py verify-access-for-user --user-name "ima.user@my.org --ps-name "App1_Deployer" --acct-id 123456789012
```
