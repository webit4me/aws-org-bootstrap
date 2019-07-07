#!/usr/bin/env python

"""
This script uses an AWS organisation admin account to create the following entities,
    to enable managing/configuringorganisation's sub accounts by terraform:
    - Terraform's backend's S3 bucket, in management account
    - Terraform's user in Identity account
    - Admin, assumable IAM roles by terraform's user, across all of the organisation's sub accounts,
      including, management and identity accounts
"""

__author__ = 'Ali Bahman'
__copyright__ = 'Copyright 2019, AWS Organisation Bootstrap'
__credits__ = ['Max Edwards']
__license__ = '{license}'
__version__ = '0.0.1'
__maintainer__ = 'Ali Bahman'
__email__ = 'abn@webit4.me'
__status__ = 'Pre-alpha'

import argparse
import json
from datetime import date, datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ModuleNotFoundError as err:
    print(err)
    print('Have you setup virtual environment and installed required modules as described in the README.md file?')
    abort_setup()

DEFAULT_BUCKET_NAME = "terraform-backend-bucket"
DEFAULT_CI_USERNAME = "ci"
DEFAULT_CI_USER_POLICY = "allow_assume_role"
DEFAULT_CI_ROLE_NAME = "ci"
DEFAULT_AWS_REGION = "eu-west-1"
DEFAULT_AWS_ORG_ACCESS_ROLE = "OrganizationAccountAccessRole"
DEFAULT_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
STORE_CREDENTIALS_AT = "credentials.txt"

# === Gather required and optional arguments
PARSER = argparse.ArgumentParser(
    description="Create required read-only and write roles on different organisation accounts"
)

PARSER.add_argument(
    "-c",
    "--check-accounts",
    help="check access to the organisation, management and all provided child accounts",
    action="store_true"
)
PARSER.add_argument(
    "-d",
    "--dry-run",
    help="only print out details of intended actions without executing them",
    action="store_true"
)

PARSER.add_argument(
    "-g", "--aws-region",
    help="AWS region name",
    action="store_true",
    default=DEFAULT_AWS_REGION
)

PARSER.add_argument(
    "organisation-admin-profile-name",
    help="AWS profile name, belongs to the organisation's admin to be used when assuming "
         "roles in other accounts to perform required actions, such as creating IAM user and roles"
)

PARSER.add_argument(
    "identity-account-id",
    help="Identity account ID to host terraform's IAM user"
)

PARSER.add_argument(
    "management-account-id",
    help="Management account ID to host terraform's backend S3 bucket and its assumable role"
)

PARSER.add_argument(
    "org-sub-account-ids",
    help="Comma separated AWS account IDs to host system admin's roles, assumable by terraform's user "
         "i.e. development, pre-production and production accounts"
)

PARSER.add_argument(
    "-r", "--role",
    help="Existing IAM role to be assumed to operate within sub accounts from the organisation account.",
    default=DEFAULT_AWS_ORG_ACCESS_ROLE
)

PARSER.add_argument(
    "-s", "--s3-bucket-name",
    help="terraform's backend 3S bucket's name, to be created on the management account",
    default=DEFAULT_BUCKET_NAME
)

PARSER.add_argument(
    "-u", "--username",
    help="A username to be created in the identity account",
    default=DEFAULT_CI_USERNAME
)

# === Global variables/constants
ARGS = PARSER.parse_args()
AWS_REGION = ARGS.__getattribute__("aws_region")
ORGANISATION_ACCESS_ROLE = ARGS.__getattribute__("role")
ORGANISATION_PROFILE_NAME = ARGS.__getattribute__("organisation-admin-profile-name")
ORG_SUB_ACCOUNT_IDS = ARGS.__getattribute__("org-sub-account-ids").split(",")
S3_BUCKET_NAME = ARGS.__getattribute__("s3_bucket_name")
USERNAME = ARGS.__getattribute__("username")

ACCOUNTS = {
    'organization': {'profile_name': ARGS.__getattribute__("organisation-admin-profile-name")},
    'management': ARGS.__getattribute__("management-account-id"),
    'identity': ARGS.__getattribute__("identity-account-id")
}

for account_id in ORG_SUB_ACCOUNT_IDS:
    ACCOUNTS["path-to-live-{}".format(ORG_SUB_ACCOUNT_IDS.index(account_id) + 1)] = account_id

CI_ROLE_POLICY_DOC_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": {
        "Action": "sts:AssumeRole",
        "Principal": {},
        "Effect": "Allow",
        "Sid": "AllowAssumeRole"
    }
}

CI_USER_POLICY_DOC_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "VisualEditor0",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": [],
    }
}

AWS_CREDENTIAL_TEMPLATE = "\n\n# Put the following in AWS credentials file, i.e. ~/.aws/credentials\n" \
                          "[{}]\n" \
                          "aws_access_key_id = {}\n" \
                          "aws_secret_access_key = {}\n"


# === Common methods ===

def abort_setup(message="Aborting setup!", exit_code=1):
    """
    Print a cross mark followed by "Aborting setup!" or any given string and exit with code 1 or the provided exit_code
    """
    print(u'\n\u2717 {}'.format(message))
    exit(exit_code)


def json_serial(obj):
    """Custom JSON serializer to handle date correctly"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


def print_completion(message='Done!'):
    """ Print a check mark followed by "Done!" or any given string """
    print(u'\u2713 {}\n'.format(message))


# === AWS Tasks ===

def client(resource,
           target_account_id=None,
           profile_name=ORGANISATION_PROFILE_NAME,
           region_name=AWS_REGION,
           role=ORGANISATION_ACCESS_ROLE):
    """
    Initiate a session, either directly in the organisation account, belongs to the provided provided AWS profile name.
    Or in the given organisation sub account, by assuming the appropriate role inside it.
    """
    if target_account_id is None or role is None:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
    else:
        response = client(resource='sts').assume_role(RoleSessionName="organisation-setup",
                                                      RoleArn="arn:aws:iam::{}:role/{}".format(target_account_id, role))

        session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])

    return session.client(resource)


def check_accounts():
    """ Check if it is possible to initiate required sessions to all of the provided organisation's accounts """
    print("\nChecking access to all accounts:\n")

    for account_label, target_account_id in sorted(ACCOUNTS.items()):
        try:
            if account_label == "organization":
                if not ARGS.dry_run:
                    print_completion(client("iam").list_account_aliases().get("AccountAliases"))
            else:
                if not ARGS.dry_run:
                    print_completion(client("iam", target_account_id).list_account_aliases().get("AccountAliases"))

        except ClientError as err:
            if err.response['Error']['Code'] == 'InvalidClientTokenId':
                if account_label == "organization":
                    print("- Check failed using defined Key & Secret for profile {}!" \
                          "\nMake sure its user has sufficient permission".format(ORGANISATION_PROFILE_NAME))
                else:
                    print("- Check failed trying to assume '{}' role on account '{}'!" \
                          "\nMake sure its user has sufficient permission".format(ORGANISATION_ACCESS_ROLE,
                                                                                  account_label))
            else:
                print("Unexpected error: %s" % err)

            exit(2)

    if not ARGS.dry_run:
        print_completion("Successfully accessed all the provided accounts")

    exit()


def create_backend_bucket(bucket_name):
    """ Create a S3 bucket in the provided management account to be used for terraform backend"""
    target_account_id = ACCOUNTS["management"]
    print('\nCreating backend\'s S3 bucket "{}" in management account (ID: {})'.format(
        bucket_name,
        target_account_id
    ))

    if ARGS.dry_run:
        print(u'\u2023 Skipped during dry-run \u2023\u2023\u2023')
        return

    try:
        client("s3", ACCOUNTS["management"]).create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
        )
        print_completion()
    except ClientError as err:
        if err.response['Error']['Code'] == 'BucketAlreadyExists':
            print("- S3 bucket \"{}\" already exists! Choose another name by providing -s argument " \
                  " and try again".format(bucket_name))
            abort_setup()
        elif err.response['Error']['Code'] == 'InvalidClientTokenId':
            print("- Failed to create S3 bucket, using defined Key & Secret for profile {}!" \
                  "\nMake sure its user has sufficient permission".format(target_account_id))
            abort_setup()
        elif err.response['Error']['Code'] == 'InvalidAccessKeyId':
            print("- Failed to authenticate credentials provided by {} profile." \
                  "\n  Make sure the Access keys is activated and credentials are valid.".format(target_account_id))
            abort_setup()
        elif err.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(u'\u2023 You already own this bucket')
        else:
            print("Unexpected error: %s" % err)
            abort_setup()


def create_and_attach_user_policy(user_name):
    """
    :type user_name: str
    :return: str Policy's ARN
    """
    # print('\nAdd inline policy to {} user, in identity account (ID: {})'.format(user_name, ACCOUNTS["identity"]))

    resources = []

    for target_account, target_account_id in ACCOUNTS.items():
        if target_account in ["organization"]:
            continue

        resources.append("arn:aws:iam::{}:role/{}".format(target_account_id, DEFAULT_CI_ROLE_NAME))

    CI_USER_POLICY_DOC_TEMPLATE["Statement"]["Resource"] = resources

    print("- Inject user's assumable inline policy")

    client("iam", ACCOUNTS["identity"]).put_user_policy(
        UserName=user_name,
        PolicyName=DEFAULT_CI_USER_POLICY,
        PolicyDocument=json.dumps(CI_USER_POLICY_DOC_TEMPLATE)
    )


def create_user(user_name):
    """
    Create terraform user in identity account
    :param user_name:
    :return:
    """

    print('\nCreating user "{}" in identity account (ID: {})'.format(user_name, ACCOUNTS["identity"]))
    if ARGS.dry_run:
        print(u'\u2023 Skipped during dry-run \u2023\u2023\u2023')
        return

    try:

        user = client("iam", ACCOUNTS["identity"]).create_user(UserName=user_name)
        CI_ROLE_POLICY_DOC_TEMPLATE["Statement"]["Principal"]["AWS"] = user["User"]["Arn"]

        print("- Generate user's credentials")
        response = client("iam", ACCOUNTS["identity"]).create_access_key(
            UserName=user_name
        )

        with open(STORE_CREDENTIALS_AT, 'w') as file:
            file.write(
                json.dumps(
                    response.get("AccessKey"),
                    default=json_serial,
                    indent=4,
                    separators=(',', ': ')
                ) + AWS_CREDENTIAL_TEMPLATE.format(
                    "identity_user_name",
                    response.get("AccessKey").get("AccessKeyId"),
                    response.get("AccessKey").get("SecretAccessKey")
                )
            )

        print(u'\u2A36 Wait for user to be created')

        waiter = client("iam", ACCOUNTS["identity"]).get_waiter('user_exists')

        waiter.wait(
            UserName=user_name,
            WaiterConfig={
                'Delay': 5,
                'MaxAttempts': 5
            }
        )

        create_and_attach_user_policy(user_name)

        print_completion()

    except ClientError as err:
        if err.response['Error']['Code'] == 'EntityAlreadyExists':

            response = client("iam", ACCOUNTS["identity"]).get_user(UserName=user_name)
            CI_ROLE_POLICY_DOC_TEMPLATE["Statement"]["Principal"]["AWS"] = response["User"]["Arn"]
            print("- User already exists >>")

            create_and_attach_user_policy(user_name)

        elif err.response['Error']['Code'] == 'InvalidClientTokenId':
            print("- Failed to create user, using defined Key & Secret for account {}!" \
                  "\nMake sure its user has sufficient permission".format(ACCOUNTS["identity"]))
            abort_setup()
        else:
            print("- Unexpected error: %s" % err)
            abort_setup()


def get_account_alias(account_id):
    """
    :param account_id:
    :return:
    """
    paginator = client("iam", account_id).get_paginator('list_account_aliases')
    for response in paginator.paginate():
        return response.get('AccountAliases', [account_id])[0]


def create_role(target_account_id, account_alias, role_name, policy_arn):
    """
    Create terraform's read and write roles in all accounts
    :param target_account_id:
    :param account_alias:
    :param role_name:
    :param policy_arn:
    :return:
    """
    try:

        print('\nCreating role "{}" in account {} (ID: {})'.format(role_name, get_account_alias(target_account_id),
                                                                   account_id))

        if ARGS.dry_run:
            print(u'\u2023 Skipped during dry-run \u2023\u2023\u2023')
            return

        assert 'AWS' in CI_ROLE_POLICY_DOC_TEMPLATE.get('Statement').get('Principal'), "Management user's ARN is not " \
                                                                                       "injected! have you called create " \
                                                                                       "user first? "

        role = client("iam", target_account_id).create_role(
            AssumeRolePolicyDocument=json.dumps(CI_ROLE_POLICY_DOC_TEMPLATE),
            Path='/',
            RoleName=role_name,
        )

        client("iam", target_account_id).attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )

        print_completion()

        return role.get("Role").get("Arn")

    except ClientError as err:
        if err.response['Error']['Code'] == 'EntityAlreadyExists':
            print("- Role already exists >>")
        elif err.response['Error']['Code'] == 'InvalidClientTokenId':
            print("- Failed to create user, using defined Key & Secret for account {}!" \
                  "\nMake sure its user has sufficient permission".format(account_alias))
        else:
            print("Unexpected error: %s" % err)


# === PROCESS ===

if ARGS.check_accounts:
    check_accounts()

create_backend_bucket(S3_BUCKET_NAME)

create_user(USERNAME)

for account, account_id in ACCOUNTS.items():
    if account in ["organization"]:
        continue

    create_role(
        target_account_id=account_id,
        account_alias=account,
        role_name=DEFAULT_CI_ROLE_NAME,
        policy_arn=DEFAULT_ADMIN_POLICY_ARN
    )
