#!/usr/bin/env python

"""setup_org_accounts.py will create required read-only and write roles on different organisation accounts"""

import argparse
import json
import time
from datetime import date, datetime


def abort_setup(message="Aborting setup!", exit_code=1):
    """
    Print a cross mark followed by "Aborting setup!" or any given string and exit with code 1 or the provided exit_code
    """
    print(u'\n\u2717 {}'.format(message))
    exit(exit_code)


try:
    import boto3
    from botocore.exceptions import ClientError
except ModuleNotFoundError as err:
    print(err)
    print('Have you setup virtual environment and installed required modules as described in the README.md file?')
    abort_setup()

__author__ = '{author}'
__copyright__ = 'Copyright {year}, {project_name}'
__credits__ = ['{credit_list}']
__license__ = '{license}'
__version__ = '{mayor}.{minor}.{rel}'
__maintainer__ = '{maintainer}'
__email__ = '{contact_email}'
__status__ = '{dev_status}'

# === Gather required and optional arguments
PARSER = argparse.ArgumentParser(
    description="Create required read-only and write roles on different organisation accounts"
)

# conflicting_group = parser.add_mutually_exclusive_group()
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
    default="eu-west-1"
)

PARSER.add_argument(
    "organisation-admin-profile-name",
    help="AWS profile name, belongs to the organisation's admin to be used when assuming "
         "roles in other accounts to take required actions"
)

PARSER.add_argument(
    "identity-account-id",
    help="identity account ID to host all users. i.e. terraform user to assume roles on other accounts to operate"
)

PARSER.add_argument(
    "management-account-id",
    help="management account ID to host shared components such as terraform's backend bucket, certificates, etc."
)

PARSER.add_argument(
    "path-to-live-account-ids",
    help="comma separated AWS account IDs to create their read-only and write roles, "
         "i.e. development, pre-production and production accounts")

PARSER.add_argument(
    "-r", "--role",
    help="existing role to be assumed within management and sub accounts from the organisation account.",
    default="OrganizationAccountAccessRole"
)

PARSER.add_argument(
    "-s", "--s3-bucket-name",
    help="terraform's backend 3S bucket's name, to be created on the management account",
    default="w4m-terraform-backend"
)

PARSER.add_argument(
    "-u", "--username",
    help="A username to be created in the identity account",
    default="terraform"
)

PARSER.add_argument(
    "-v",
    "--verbose",
    help="increase output verbosity",
    action="store_true"
)

# === Global variables/constants
ARGS = PARSER.parse_args()
AWS_REGION = ARGS.__getattribute__("aws_region")
CREDENTIALS_FILE_NAME = "credentials.txt"
DEBUGGING_SUFFIX = ""
MANAGEMENT_READ_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
MANAGEMENT_READ_ROLE_NAME = "account-read{}".format(DEBUGGING_SUFFIX)
MANAGEMENT_WRITE_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
MANAGEMENT_WRITE_ROLE_NAME = "account-write{}".format(DEBUGGING_SUFFIX)
ORGANISATION_ACCESS_ROLE = ARGS.__getattribute__("role")
ORGANISATION_PROFILE_NAME = ARGS.__getattribute__("organisation-admin-profile-name")
PATH_TO_LIVE_ACCOUNT_IDS = ARGS.__getattribute__("path-to-live-account-ids").split(",")
S3_BUCKET_NAME = ARGS.__getattribute__("s3_bucket_name")
USERNAME = ARGS.__getattribute__("username")

ACCOUNTS = {
    'organization': {'profile_name': ARGS.__getattribute__("organisation-admin-profile-name")},
    'management': ARGS.__getattribute__("management-account-id"),
    'identity': ARGS.__getattribute__("identity-account-id")
}

ASSUMABLE_ROLE_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": {
        "Action": "sts:AssumeRole",
        "Principal": {},
        "Effect": "Allow",
        "Sid": "AllowAssumeRole"
    }
}

USER_ASSUME_ROLE_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": []
    }
}

AWS_CREDENTIAL_TEMPLATE = "\n\n# Put the following in AWS credentials file, i.e. ~/.aws/credentials\n" \
                          "[{}]\n" \
                          "aws_access_key_id = {}\n" \
                          "aws_secret_access_key = {}\n"

for account_id in PATH_TO_LIVE_ACCOUNT_IDS:
    ACCOUNTS["path-to-live-{}".format(PATH_TO_LIVE_ACCOUNT_IDS.index(account_id) + 1)] = account_id


# === Common methods ===
def json_serial(obj):
    """Custom JSON serializer to handle date correctly"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


def json_print(message, default=json_serial, indent=4, separators=(',', ': ')):
    """ Generic printer, capable of pretty printing JSON including date & datetime objects"""
    print(json.dumps(message,
                     default=default,
                     indent=indent,
                     separators=separators))


def report(message):
    """ Use p() to print the given message only if verbose flag is set """
    if ARGS.dry_run or ARGS.verbose:
        print(message)


def print_completion(message='Done!'):
    """ Print a check mark followed by "Done!" or any given string """
    print(u'\u2713 {}\n'.format(message))


def pause(seconds):
    """
    To pause the process after printing a stop-watch followed by a message to inform how many seconds delay is expected
    """
    print(u'\n\u2A36 Pausing for {} seconds'.format(seconds))
    time.sleep(seconds)


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
                report("{} (Profile name: {})".format(account_label, target_account_id.get('profile_name')))
                if not ARGS.dry_run:
                    print_completion(client("iam").list_account_aliases().get("AccountAliases"))
            else:
                report("{} (Account ID: {})".format(account_label, target_account_id))
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
        print(u'\u2023\u2023\u2023 Skip')
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


def create_user(user_name):
    """
    Create terraform user in identity account
    :param user_name:
    :return:
    """
    print('\nCreating user "{}" in account "{}"'.format(user_name, ACCOUNTS["identity"]))
    try:

        response = client("iam", ACCOUNTS["identity"]).create_user(UserName=user_name)
        ASSUMABLE_ROLE_TEMPLATE["Statement"]["Principal"]["AWS"] = response["User"]["Arn"]

        response = client("iam", ACCOUNTS["identity"]).create_access_key(
            UserName=user_name
        )

        with open(CREDENTIALS_FILE_NAME, 'w') as file:
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

        print_completion()
        pause(10)
    except ClientError as err:
        if err.response['Error']['Code'] == 'EntityAlreadyExists':

            response = client("iam", ACCOUNTS["identity"]).get_user(UserName=user_name)
            ASSUMABLE_ROLE_TEMPLATE["Statement"]["Principal"]["AWS"] = response["User"]["Arn"]
            print("- User already exists >>")
        elif err.response['Error']['Code'] == 'InvalidClientTokenId':
            print("- Failed to create user, using defined Key & Secret for account {}!" \
                  "\nMake sure its user has sufficient permission".format(ACCOUNTS["identity"]))
            abort_setup()
        else:
            print("- Unexpected error: %s" % err)
            abort_setup()


def create_role(tagert_account_id, account_alias, role_name, policy_arn):
    """
    Create terraform's read and write roles in all accounts
    :param tagert_account_id:
    :param account_alias:
    :param role_name:
    :param policy_arn:
    :return:
    """
    try:
        assert 'AWS' in ASSUMABLE_ROLE_TEMPLATE.get('Statement').get('Principal'), "Management user's ARN is not " \
                                                                                   "injected! have you called create " \
                                                                                   "user first? "
        print('\nCreating role "{}" in account "{}"'.format(role_name, account_alias))

        role = client("iam", tagert_account_id).create_role(
            AssumeRolePolicyDocument=json.dumps(ASSUMABLE_ROLE_TEMPLATE),
            Path='/',
            RoleName=role_name,
        )

        client("iam", tagert_account_id).attach_role_policy(
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


def create_write_role(target_account_id, account_alias):
    """
    Create terraform write role in the given account
    :param target_account_id:
    :param account_alias:
    :return:
    """
    return create_role(
        tagert_account_id=target_account_id,
        account_alias=account_alias,
        role_name=MANAGEMENT_WRITE_ROLE_NAME,
        policy_arn=MANAGEMENT_WRITE_POLICY_ARN
    )


def create_read_role(target_account_id, account_alias):
    """
    Create terraform read role in the given account
    :param target_account_id:
    :param account_alias:
    :return:
    """
    return create_role(
        tagert_account_id=target_account_id,
        account_alias=account_alias,
        role_name=MANAGEMENT_READ_ROLE_NAME,
        policy_arn=MANAGEMENT_READ_POLICY_ARN
    )


# === PROCESS ===

if ARGS.check_accounts:
    check_accounts()

create_backend_bucket(S3_BUCKET_NAME)

create_user(USERNAME)

for account, account_id in ACCOUNTS.items():
    if account in ["organization"]:
        continue

    create_write_role(account_id, account)
    create_read_role(account_id, account)
