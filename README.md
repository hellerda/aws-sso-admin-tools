# Overview

This project is a set of tools to help you perform administrative management in AWS Identity Center.  With it you can manage the following resources:

- Users and groups
- Permission sets
- Account assignments
- Registered OIDC or SAML applications

The program supports most operations you can do via the AWS management console or AWS CLI.  But the program has several advantages over AWS CLI:

- Operations that require several commands in AWS CLI can be done in single command in the program.
- The AWS CLI commands generally require user and group ids or permission set or application Arns as input.  The program includes utility functions to do the conversion, so you can specify input and display output using the "friendly names" for these objects.
- The program supports attach/detach a *list* of managed policies, whereas AWS CLI only accepts one at a time.
- The program provides several views that are not available or difficult to generate through the AWS Console or AWS CLI, like the ability to list all account assignments for a user, group or permission set.


# Build and install

```
$ pip install setuptools build
$ cd <project directory>
$ python -m build
$ pip install ./dist/aws_sso_admin_tools-0.1.0-py3-none-any.whl
```

You will now have the ```aws-sso-admin``` executable installed.  If not found, run ```pip show aws-sso-admin-tools``` and check the installed "Location".  The executable should be installed in the ```./bin``` directory that is the peer of the displayed ```./lib``` directory.  Make sure this directory is in your path.


# Running the program

To see the list of available commands, run:
```
$ aws-sso-admin help
```
Most commands require input values to be set on the command line.  To see the supported options, refer to the examples below or run:
```
$ aws-sso-admin <command> --help
```


# Examples

## Simple lookup operations
```
aws-sso-admin lookup-user-id --user-name "ima.user@my.org"
aws-sso-admin lookup-group-id --group-name "App1_Deployers"
aws-sso-admin lookup-ps-arn --ps-name "AdministratorAccess"
aws-sso-admin lookup-app-arn --app-name "My-Custom-App"

aws-sso-admin lookup-user-name --user-id "11111111-1111-1111-1111-111111111111"
aws-sso-admin lookup-group-name --group-id "22222222-2222-2222-2222-222222222222"
aws-sso-admin lookup-ps-name --ps-arn "arn:aws:sso:::permissionSet/ssoins-abcdef1234567890/ps-1234567890123456"
aws-sso-admin lookup-app-name --app-arn "arn:aws:sso::123456789012:application/ssoins-abcdef1234567890/apl-a1b2c3d4e5f67890"
```

## User and Group operations

NOTE: Any operation that modifies a User or Group resource can result in inconsistences or conflicts when your Identity Center uses an external IdP like MS Entra.  If this is not intended you should disallow these operations in IAM policy.  All the r/o operations are safe, though.

NOTE: For bulk operations, update ```user_list``` in the program (see "Customize this").
```
aws-sso-admin create-group --group-name "App1_Deployers" --group-desc "Can deploy the sample app"
aws-sso-admin describe-group --group-name "App1_Deployers"
aws-sso-admin delete-group --group-name "App1_Deployers"

aws-sso-admin list-users
aws-sso-admin list-groups
aws-sso-admin describe-user --user-name "ima.user@my.org"
aws-sso-admin list-group-memberships --group-name "App1_Deployers"
aws-sso-admin list-all-group-memberships-for-user --user-name "ima.user@my.org"

# Bulk operations on users:
aws-sso-admin create-users
aws-sso-admin get-users
aws-sso-admin delete-users
aws-sso-admin create-group-memberships --group-name "App1_Deployers"
aws-sso-admin get-group-memberships --group-name "App1_Deployers"
aws-sso-admin delete-group-memberships --group-name "App1_Deployers"

# Operations on individual users:
aws-sso-admin create-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
aws-sso-admin get-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
aws-sso-admin delete-group-membership --group-name "App1_Deployers" --user-name "ima.user@my.org"
```

## Permission Set operations

NOTE: For all ops that accept ```--tags```, ```--policy```, ```--policy-arns``` or ```--cm-policy```: If the option is omitted, the program looks for the input to be set in the program (see "Customize this").  If no input is set, the program throws an error.
```
aws-sso-admin create-ps --ps-name "App1_Deployer"
aws-sso-admin create-ps --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H

aws-sso-admin update-ps --ps-name "App1_Deployer" --ps-desc "Sample app deployer role" --ps-durn PT2H

aws-sso-admin put-ps-inline-policy --ps-name "App1_Deployer"
aws-sso-admin attach-ps-managed-policies --ps-name "App1_Deployer"
aws-sso-admin attach-ps-customer-managed-policies --ps-name "App1_Deployer"

aws-sso-admin describe-ps --ps-name "App1_Deployer"
aws-sso-admin get-ps-inline-policy --ps-name "App1_Deployer" | jq -r .InlinePolicy | jq
aws-sso-admin list-ps-managed-policies --ps-name "App1_Deployer"
aws-sso-admin list-ps-customer-managed-policies --ps-name "App1_Deployer"
aws-sso-admin list-ps-tags --ps-name "App1_Deployer"

aws-sso-admin delete-ps-inline-policy --ps-name "App1_Deployer"
aws-sso-admin detach-ps-managed-policies --ps-name "App1_Deployer"
aws-sso-admin detach-ps-customer-managed-policies --ps-name "App1_Deployer"

aws-sso-admin delete-ps --ps-name "App1_Deployer"

aws-sso-admin provision-ps --ps-name "App1_Deployer"
aws-sso-admin provision-ps --ps-name "App1_Deployer" --acct-id 123456789012
```

## Account Assignment operations

```
aws-sso-admin create-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012
aws-sso-admin delete-account-assignment --ps-name "App1_Deployer" --group-name "App1_Deployers" --acct-id 123456789012

aws-sso-admin provision-permission-set --ps-name "App1_Deployer"
aws-sso-admin provision-permission-set --ps-name "App1_Deployer" --acct-id 123456789012

aws-sso-admin list-assigned-principals-for-ps-in-account --ps-name "App1_Deployer" --acct-id 123456789012

aws-sso-admin list-accounts-for-provisioned-permission-set --ps-name "App1_Deployer"
aws-sso-admin list-all-acct-assignments-for-provisioned-permission-set --ps-name "App1_Deployer"

aws-sso-admin list-all-permission-sets-in-org
aws-sso-admin list-all-acct-assignments-for-ps-in-org

aws-sso-admin list-all-acct-assignments-for-principal --user-name "ima.user@my.org"
aws-sso-admin list-all-acct-assignments-for-principal --group-name "App1_Deployers"

aws-sso-admin list-permission-sets-provisioned-to-account --acct-id 123456789012
aws-sso-admin list-all-permission-set-assignments-in-account --acct-id 123456789012

aws-sso-admin list-all-permission-set-assignments-in-ou --ou-name "IT"
aws-sso-admin list-all-permission-set-assignments-in-ou --ou-name "Sandbox"

aws-sso-admin verify-access-for-user --user-name "ima.user@my.org --ps-name "App1_Deployer" --acct-id 123456789012
```

## Application management operations

```
aws-sso-admin list-ttis
aws-sso-admin describe-tti --tti-name "My-TrustedTokenIssuer"

aws-sso-admin list-applications
aws-sso-admin describe-application --app-name "My-Custom-App"
aws-sso-admin list-application-assignments --app-name "My-Custom-App"
aws-sso-admin list-application-grants --app-name "My-Custom-App"
aws-sso-admin list-application-access-scopes --app-name "My-Custom-App"
aws-sso-admin list-application-auth-methods --app-name "My-Custom-App"
```

# Advanced operations

## Advanced permission set CRUD operations

### All the supported ways to "create" with tags
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
### All the supported ways to "tag" an existing PS
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
### All the supported ways to "untag" an existing PS
```
aws-sso-admin untag-ps --ps-name "App1_Deployer" --tag-keys "Environment,Application"
```
### All the supported ways to "put-inline-policy"
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
### All the supported ways to "attach/detach-managed-policies"

NOTE: The identical syntax is supported for ```attach-ps-managed-policies``` and ```detach-ps-managed-policies```.
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
### All the supported ways to "attach/detach-customer-managed-policies"
NOTE: The identical syntax is supported for ```attach-ps-customer-managed-policies``` and ```detach-ps-customer-managed-policies```.
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
