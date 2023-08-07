# Overview

This project is a set of tools to help you manage Users and Groups, and Permission Sets and Account Assignments in AWS Identity Center.  It supports all the operations you can do in AWS management console, from CLI.  While you can do these operations using AWS CLI as well, some operations require several commands to complete.  Also, it is helpful to have utils to convert user and group names to Id, and PS names to Arn, and so on.  All these helper utils are included.  You can specify input values, and display output values using "friendly names".

There are three scripts:
```
manage-account-assignments.py
manage-permission-set.py
manage-users-groups.py
```

Each script supports a set of commands.  To see the supported commands, run the script with ```--help``` or refer to the examples below.

Some commands require input values.  Use the available options to specify the values on the command line.  To see the supported options, run the script with ```--help``` or refer to the examples below.

Some input options, such as bulk list of users to operate on, can only be modified in the program.  Permission Set IAM inline or attached policy, or PS tags to apply, can be provided by either command line or file.


# Examples

## User and Group operations

NOTE: If your Identity Center uses an external IdP, some operations such as create-user or create-group may produce changes that are not in sync with your external IdP.  See Identity Center documentation.
```
python manage-users-groups.py create-group --group-name "App1_Deployers" --group-desc "Can deploy the sample app"
python manage-users-groups.py create-users
python manage-users-groups.py create-group-memberships --group-name "App1_Deployers"

python manage-users-groups.py list-users
python manage-users-groups.py list-groups
python manage-users-groups.py get-users
python manage-users-groups.py describe-user --user-name "ima.user@my.org"
python manage-users-groups.py describe-group --group-name "App1_Deployers"
python manage-users-groups.py get-group-memberships --group-name "App1_Deployers"
python manage-users-groups.py list-group-memberships --group-name "App1_Deployers"

python manage-users-groups.py delete-group-memberships --group-name "App1_Deployers"
python manage-users-groups.py delete-users
python manage-users-groups.py delete-group --group-name "App1_Deployers"
```

## Permission Set operations
```
python manage-permission-set.py create --ps-name "App1_Deployer"
python manage-permission-set.py attach-managed-policy --ps-name "App1_Deployer"
python manage-permission-set.py put-inline-policy --ps-name "App1_Deployer" \
--policy "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"ssm:DescribeParameters\", \"Resource\": \"*\" } ] }"

python manage-permission-set.py describe --ps-name "App1_Deployer"
python manage-permission-set.py list-managed-policies --ps-name "App1_Deployer"
python manage-permission-set.py get-inline-policy --ps-name "App1_Deployer"
python manage-permission-set.py list-tags --ps-name "App1_Deployer"

python manage-permission-set.py delete-inline-policy --ps-name "App1_Deployer"
python manage-permission-set.py detach-managed-policy --ps-name "App1_Deployer"
python manage-permission-set.py delete --ps-name "App1_Deployer"

python manage-permission-set.py provision --ps-name "App1_Deployer"
python manage-permission-set.py provision --ps-name "App1_Deployer" --acct-id 123456789012

python manage-permission-set.py describe --ps-name "AdministratorAccess"
python manage-permission-set.py describe --ps-name "ReadOnlyAccess"
python manage-permission-set.py describe --ps-name "App1_Deployer"
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

python manage-account-assignments.py list-all-acct-assignments-for-ps-in-org

python manage-account-assignments.py list-all-acct-assignments-for-principal --user-name "ima.user@my.org"
python manage-account-assignments.py list-all-acct-assignments-for-principal --group-name "App1_Deployers"

python manage-account-assignments.py list-permission-sets-provisioned-to-account --acct-id 123456789012
python manage-account-assignments.py list-all-permission-set-assignments-in-account --acct-id 123456789012

python manage-account-assignments.py list-all-permission-set-assignments-in-ou --ou-name "IT"
python manage-account-assignments.py list-all-permission-set-assignments-in-ou --ou-name "Sandbox"
```
