# aws-org-bootstrap

To bootstrap an AWS organisation accounts with required user, roles and S3 bucket required by terraform 

**Setup** virtual environment and install required modules

```bash
virtualenv venv --python=python3
source ./venv/bin/activate
pip install boto3
```

**Run** script

```bash
./bootstrap.py abn-webit4me-organisation 744139270042 136577907298 795053184401,281934868217,125801569587 -v -s alireza-test-bucket
```

**Contribute**

- Edit
- Test
- Lint
    ```bash
    pip install pylint
    pylint bootstrap.py
    ```
- commit
